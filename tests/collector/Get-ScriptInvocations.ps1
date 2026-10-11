<#
  PARSE (never execute) a PowerShell script and emit, as JSON, everything the
  read-only gate (tests/test_collector_readonly.py) reasons about:

  1. `ast_rows` + `source_sha256`: a complete, ORDER-PRESERVING serialization
     of the whole syntax tree (one row per node: depth, role in the parent,
     node type, every semantically relevant property) and a SHA-256 of the
     source text with only CRLF->LF normalized. This is the golden layer.
     The serializer is driven by $NodeProperties, an explicit table of every
     concrete Ast type; a node type missing from the table is emitted as an
     UNSUPPORTED row (and rejected by the gate). `-Describe` prints the table
     next to this runtime's Ast reflection data so a test can prove coverage.
  2. Projections for the semantic layer: commands, member calls, redirections,
     variable bindings, member/index assignments, functions, type names, each
     with its enclosing scope ("<script>" or the function name, plus "/{}" per
     enclosing script block) and, for commands and member calls, the
     control-flow context (enclosing functions, conditions, loops, try blocks
     and the early-exit guards that precede it).

  Provenance: the serializer table, Add-AstRows, Format-ScalarValue,
  Get-NodeContext/Get-GuardText and the source digest are copied from gpo-lens
  tests/powershell/Get-ScriptCallInventory.ps1 (commit 64411db) and adapted to
  this file's projection format.

  Variable names in the projections are lower-cased with a SCOPE qualifier
  ($script:, $local:, $private:, $global:, $variable:, $using:) stripped, so
  PowerShell's case-insensitive resolution cannot dodge a pin; the qualifier is
  reported separately. A provider-drive name (${alias:x}, $env:x, ${C:\x}) is
  kept whole and reported with its drive, so it never collides with a pin.

  Modes:
    -Path <file>                    one inventory object
    -Many -Path <f1>,<f2>,...       a JSON array of inventory objects
    -Many -AstOnly -Path ...        array of {path, source_sha256, parse_errors, ast_rows}
    -Many -Sites -Path ...          array of mutation sites (completeness meta-test)
    -Describe                       serializer table vs. runtime reflection

  Uses [Parser]::ParseFile only: nothing in the target script runs.
#>
param(
  [Parameter(ValueFromRemainingArguments)] [string[]] $Path,
  [switch] $Many,
  [switch] $AstOnly,
  [switch] $Sites,
  [switch] $Describe,
  # Emit each file's source with the case of command/function-call names,
  # parameter names and variable names flipped (bareword VALUES, quoted strings,
  # type literals and member names left intact). Used by the case-insensitivity
  # meta-test: a case-variant of any NAME must get the same verdict.
  [switch] $SwapNames
)

$ErrorActionPreference = 'Stop'
$A = 'System.Management.Automation.Language'

# ---------------------------------------------------------------------------
# Full-tree serialization table: node type -> ordered properties. Every public
# property of every concrete Ast type must be listed here or in
# $ExcludedProperties (tests/test_collector_readonly.py proves it against the
# running PowerShell's reflection data).
# ---------------------------------------------------------------------------
$InvokeMemberProps = @('Static', 'NullConditional', 'Expression', 'Member', 'GenericTypeArguments', 'Arguments')
$NodeProperties = @{
  'ArrayExpressionAst'                = @('SubExpression')
  'ArrayLiteralAst'                   = @('Elements')
  'AssignmentStatementAst'            = @('Operator', 'Left', 'Right')
  'AttributeAst'                      = @('TypeName', 'PositionalArguments', 'NamedArguments')
  'AttributedExpressionAst'           = @('Attribute', 'Child')
  'BaseCtorInvokeMemberExpressionAst' = $InvokeMemberProps
  'BinaryExpressionAst'               = @('Operator', 'Left', 'Right')
  'BlockStatementAst'                 = @('Kind', 'Body')
  'BreakStatementAst'                 = @('Label')
  'CatchClauseAst'                    = @('IsCatchAll', 'CatchTypes', 'Body')
  'CommandAst'                        = @('InvocationOperator', 'DefiningKeyword', 'CommandElements', 'Redirections')
  'CommandExpressionAst'              = @('Expression', 'Redirections')
  'CommandParameterAst'               = @('ParameterName', 'Argument')
  'ConfigurationDefinitionAst'        = @('ConfigurationType', 'InstanceName', 'Body')
  'ConstantExpressionAst'             = @('Value')
  'ContinueStatementAst'              = @('Label')
  'ConvertExpressionAst'              = @('Type', 'Child')
  'DataStatementAst'                  = @('Variable', 'CommandsAllowed', 'Body')
  'DoUntilStatementAst'               = @('Label', 'Body', 'Condition')
  'DoWhileStatementAst'               = @('Label', 'Body', 'Condition')
  'DynamicKeywordStatementAst'        = @('CommandElements')
  'ErrorExpressionAst'                = @('NestedAst')
  'ErrorStatementAst'                 = @('Kind', 'Flags', 'Conditions', 'Bodies', 'NestedAst')
  'ExitStatementAst'                  = @('Pipeline')
  'ExpandableStringExpressionAst'     = @('StringConstantType', 'Value', 'NestedExpressions')
  'FileRedirectionAst'                = @('FromStream', 'Append', 'Location')
  'ForEachStatementAst'               = @('Label', 'Flags', 'Variable', 'Condition', 'ThrottleLimit', 'Body')
  'ForStatementAst'                   = @('Label', 'Initializer', 'Condition', 'Iterator', 'Body')
  'FunctionDefinitionAst'             = @('IsFilter', 'IsWorkflow', 'Name', 'Parameters', 'Body')
  'FunctionMemberAst'                 = @('Name', 'MethodAttributes', 'IsPublic', 'IsPrivate', 'IsHidden', 'IsStatic',
    'IsConstructor', 'Attributes', 'ReturnType', 'Parameters', 'Body')
  'HashtableAst'                      = @('KeyValuePairs')
  'IfStatementAst'                    = @('Clauses', 'ElseClause')
  'IndexExpressionAst'                = @('NullConditional', 'Target', 'Index')
  'InvokeMemberExpressionAst'         = $InvokeMemberProps
  'MemberExpressionAst'               = @('Static', 'NullConditional', 'Expression', 'Member')
  'MergingRedirectionAst'             = @('FromStream', 'ToStream')
  'NamedAttributeArgumentAst'         = @('ArgumentName', 'ExpressionOmitted', 'Argument')
  'NamedBlockAst'                     = @('BlockKind', 'Unnamed', 'Statements', 'Traps')
  'ParamBlockAst'                     = @('Attributes', 'Parameters')
  'ParameterAst'                      = @('Attributes', 'Name', 'DefaultValue')
  'ParenExpressionAst'                = @('Pipeline')
  'PipelineAst'                       = @('Background', 'PipelineElements')
  'PipelineChainAst'                  = @('Operator', 'Background', 'LhsPipelineChain', 'RhsPipeline')
  'PropertyMemberAst'                 = @('Name', 'PropertyAttributes', 'IsPublic', 'IsPrivate', 'IsHidden', 'IsStatic',
    'PropertyType', 'Attributes', 'InitialValue')
  'ReturnStatementAst'                = @('Pipeline')
  'ScriptBlockAst'                    = @('ScriptRequirements', 'Attributes', 'UsingStatements', 'ParamBlock',
    'DynamicParamBlock', 'BeginBlock', 'ProcessBlock', 'EndBlock', 'CleanBlock')
  'ScriptBlockExpressionAst'          = @('ScriptBlock')
  'StatementBlockAst'                 = @('Statements', 'Traps')
  'StringConstantExpressionAst'       = @('StringConstantType', 'Value')
  'SubExpressionAst'                  = @('SubExpression')
  'SwitchStatementAst'                = @('Label', 'Flags', 'Condition', 'Clauses', 'Default')
  'TernaryExpressionAst'              = @('Condition', 'IfTrue', 'IfFalse')
  'ThrowStatementAst'                 = @('IsRethrow', 'Pipeline')
  'TrapStatementAst'                  = @('TrapType', 'Body')
  'TryStatementAst'                   = @('Body', 'CatchClauses', 'Finally')
  'TypeConstraintAst'                 = @('TypeName')
  'TypeDefinitionAst'                 = @('Name', 'TypeAttributes', 'IsEnum', 'IsClass', 'IsInterface', 'Attributes',
    'BaseTypes', 'Members')
  'TypeExpressionAst'                 = @('TypeName')
  'UnaryExpressionAst'                = @('TokenKind', 'Child')
  'UsingExpressionAst'                = @('SubExpression')
  'UsingStatementAst'                 = @('UsingStatementKind', 'Name', 'Alias', 'ModuleSpecification')
  'VariableExpressionAst'             = @('VariablePath', 'Splatted')
  'WhileStatementAst'                 = @('Label', 'Condition', 'Body')
}
# Properties deliberately not serialized, with the reason (checked by the test).
$ExcludedProperties = [ordered]@{
  '*.Parent'                       = 'back-reference to the enclosing node (structure is the row nesting)'
  '*.Extent'                       = 'source position/text; positions are not behaviour and the text is the children'
  '*.ErrorPosition'                = 'source position of an operator token (an IScriptExtent)'
  '*.StaticType'                   = 'derived by the parser from the node type, constant value or cast type'
  'ConvertExpressionAst.Attribute' = 'the same object as ConvertExpressionAst.Type'
}
# Tuple-valued collections: friendly names for Item1/Item2.
$TupleRoles = @{
  'IfStatementAst.Clauses'     = @('Condition', 'Body')
  'SwitchStatementAst.Clauses' = @('Pattern', 'Body')
  'HashtableAst.KeyValuePairs' = @('Key', 'Value')
}

function ConvertTo-Lf([string]$Text) {
  if ($null -eq $Text) { return $null }
  return $Text.Replace("`r`n", "`n")
}

function Format-ScalarValue {
  # Returns @($ok, $value). $value is a string, a bool, or a string array.
  param($Value)
  if ($Value -is [string]) { return @($true, (ConvertTo-Lf $Value)) }
  if ($Value -is [bool]) { return @($true, $Value) }
  if ($Value -is [enum]) { return @($true, $Value.ToString()) }
  if ($Value -is [System.Management.Automation.Language.ITypeName]) { return @($true, $Value.FullName) }
  if ($Value -is [System.Management.Automation.VariablePath]) { return @($true, $Value.UserPath) }
  if ($Value -is [System.Management.Automation.Language.Token]) {
    return @($true, ('{0}:{1}' -f $Value.Kind, (ConvertTo-Lf $Value.Text)))
  }
  if ($Value -is [System.Management.Automation.Language.DynamicKeyword]) { return @($true, $Value.Keyword) }
  if ($Value -is [System.Management.Automation.Language.ScriptRequirements]) {
    $parts = @()
    foreach ($p in ($Value.GetType().GetProperties() | Sort-Object Name)) {
      $v = $p.GetValue($Value)
      if ($null -eq $v) { continue }
      if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
        $items = @($v | ForEach-Object {
            if ($_.PSObject.Properties['Name'] -and -not ($_ -is [string])) { "$($_.Name) $($_.Version)" } else { [string]$_ }
          })
        if ($items.Count -eq 0) { continue }
        $parts += ('{0}=[{1}]' -f $p.Name, ($items -join ', '))
      } elseif ($v -is [bool]) {
        if ($v) { $parts += $p.Name }
      } else {
        $parts += ('{0}={1}' -f $p.Name, [string]$v)
      }
    }
    return @($true, ($parts -join '; '))
  }
  if ($Value -is [ValueType]) {
    $text = if ($Value -is [System.IFormattable]) {
      $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture)
    } else { [string]$Value }
    return @($true, ('{0}:{1}' -f $Value.GetType().Name, $text))
  }
  return @($false, $Value.GetType().FullName)
}

# Pre-order, order-preserving walk (iterative: a recursive PowerShell function
# per node is several times slower). Emits the same rows as gpo-lens's
# recursive Add-AstRows.
function Add-AstRows {
  param($Node, [int]$Depth, [string]$Role, $Rows, $Unsupported)
  $astType = [System.Management.Automation.Language.Ast]
  $stack = [System.Collections.Generic.Stack[object]]::new()
  $stack.Push(@($Node, $Depth, $Role))
  while ($stack.Count -gt 0) {
    $item = $stack.Pop()
    $node = $item[0]; $depth = $item[1]; $role = $item[2]
    $typeName = $node.GetType().Name
    $props = $NodeProperties[$typeName]
    if ($null -eq $props) {
      $Unsupported.Add($typeName)
      $Rows.Add(@($depth, $role, "UNSUPPORTED:$typeName", @(), (($node.Extent.Text -replace '\s+', ' ').Trim())))
      continue
    }
    $attrs = [System.Collections.Generic.List[object]]::new()
    $children = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $props) {
      $value = $node.$p  # $null when the property is absent (e.g. CleanBlock in 5.1)
      if ($null -eq $value) { continue }
      if ($value -is $astType) {
        $children.Add(@($p, $value))
        continue
      }
      if ($value -is [string]) { $attrs.Add(@($p, (ConvertTo-Lf $value))); continue }
      if ($value -is [bool]) { if ($value) { $attrs.Add(@($p, $true)) }; continue }  # false is the default; omitted
      if ($value -is [enum]) { $attrs.Add(@($p, $value.ToString())); continue }
      if ($value -is [System.Collections.IDictionary]) {
        # ErrorStatementAst.Flags: name -> Tuple<Token, Ast>, emitted sorted.
        $names = @()
        foreach ($k in (@($value.Keys) | Sort-Object)) {
          $entry = $value[$k]
          $names += [string]$k
          if ($null -ne $entry.Item2) { $children.Add(@("$p[$k]", $entry.Item2)) }
        }
        $attrs.Add(@($p, [string[]]$names))
        continue
      }
      if ($value -is [System.Collections.IEnumerable]) {
        $scalars = @()
        foreach ($elem in $value) {
          if ($null -eq $elem) { continue }
          if ($elem -is $astType) {
            $children.Add(@($p, $elem))
          } elseif ($elem.GetType().Name -eq 'Tuple`2') {
            $names = $TupleRoles["$typeName.$p"]
            if ($null -eq $names) { $names = @('Item1', 'Item2') }
            if ($null -ne $elem.Item1) { $children.Add(@("$p.$($names[0])", $elem.Item1)) }
            if ($null -ne $elem.Item2) { $children.Add(@("$p.$($names[1])", $elem.Item2)) }
          } else {
            $r = Format-ScalarValue $elem
            if (-not $r[0]) { $Unsupported.Add("$typeName.$p item $($r[1])") }
            $scalars += [string]$r[1]
          }
        }
        if ($scalars.Count -gt 0) { $attrs.Add(@($p, [string[]]$scalars)) }
        continue
      }
      $r = Format-ScalarValue $value
      if (-not $r[0]) {
        $Unsupported.Add("$typeName.$p value $($r[1])")
        $attrs.Add(@($p, "UNSUPPORTED:$($r[1])"))
        continue
      }
      $attrs.Add(@($p, $r[1]))
    }
    $Rows.Add(@($depth, $role, $typeName, $attrs.ToArray()))
    for ($ci = $children.Count - 1; $ci -ge 0; $ci--) {
      $stack.Push(@($children[$ci][1], ($depth + 1), $children[$ci][0]))
    }
  }
}

if ($Describe) {
  $asm = [System.Management.Automation.Language.Ast].Assembly
  $types = @()
  foreach ($t in ($asm.GetTypes() | Where-Object {
        $_.IsPublic -and -not $_.IsAbstract -and [System.Management.Automation.Language.Ast].IsAssignableFrom($_)
      } | Sort-Object Name)) {
    $types += [pscustomobject][ordered]@{
      name       = $t.Name
      properties = @($t.GetProperties([Reflection.BindingFlags]'Public,Instance') |
          ForEach-Object { $_.Name } | Sort-Object -Unique)
    }
  }
  $table = [ordered]@{}
  foreach ($k in ($NodeProperties.Keys | Sort-Object)) { $table[$k] = @($NodeProperties[$k]) }
  [pscustomobject][ordered]@{
    ps_version                     = $PSVersionTable.PSVersion.ToString()
    ast_types                      = $types
    table                          = [pscustomobject]$table
    excluded                       = @($ExcludedProperties.Keys)
    script_requirements_properties = @([System.Management.Automation.Language.ScriptRequirements].GetProperties() |
        ForEach-Object { $_.Name } | Sort-Object)
  } | ConvertTo-Json -Depth 6 -Compress
  return
}

function Get-SourceFacts([string]$File) {
  $bytes = [System.IO.File]::ReadAllBytes($File)
  $nonAscii = 0
  foreach ($b in $bytes) { if ($b -gt 127) { $nonAscii++ } }
  $text = ConvertTo-Lf ([System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF))
  $hash = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = ([System.BitConverter]::ToString($hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))) -replace '-', '').ToLowerInvariant()
  } finally { $hash.Dispose() }
  return @($digest, $nonAscii)
}

# ---------------------------------------------------------------------------
# Projection helpers.
# ---------------------------------------------------------------------------
function _flat([string]$s) { ($s -replace '\s+', ' ').Trim() }

# Lower-cased variable name; a scope qualifier is stripped (reported by
# _qualifier), a provider-drive path is kept whole.
$ScopePrefixes = @('script:', 'local:', 'private:', 'global:', 'variable:', 'using:')
function _varName($v) {
  $p = $v.VariablePath
  $name = ([string]$p.UserPath).ToLowerInvariant()
  if ($p.IsDriveQualified -or -not $p.IsVariable) { return $name }
  foreach ($prefix in $ScopePrefixes) {
    if ($name.StartsWith($prefix)) { return $name.Substring($prefix.Length) }
  }
  return $name
}
function _qualifier($v) {
  $p = $v.VariablePath
  if ($p.IsDriveQualified -or -not $p.IsVariable) { return 'drive' }
  if ($p.IsUnqualified) { return '' }
  if ($p.IsScript) { return 'script' }
  if ($p.IsLocal) { return 'local' }
  if ($p.IsPrivate) { return 'private' }
  if ($p.IsGlobal) { return 'global' }
  $lower = ([string]$p.UserPath).ToLowerInvariant()
  foreach ($prefix in $ScopePrefixes) { if ($lower.StartsWith($prefix)) { return $prefix.TrimEnd(':') } }
  return 'other'
}
function _drive($v) { [string]$v.VariablePath.DriveName }

# A script block is a NEW (isolated) scope for binding purposes only when it is
# invoked with the call operator `& { ... }`. ForEach-Object / Where-Object
# (and %/? ) process blocks, `. { ... }` dot-sourcing, .ForEach()/.Where()
# method blocks and a block stored in a variable all run in (or dot-source into)
# the CALLER's scope, so an unqualified assignment inside them rebinds the
# enclosing variable. Anything we cannot prove is `& { ... }` is treated as the
# caller scope (strict default), so such a binding collapses onto the enclosing
# pinned key rather than hiding in a child scope.
function _isIsolatedBlock($sbe) {
  $p = $sbe.Parent
  return ($p -is [System.Management.Automation.Language.CommandAst] -and
    [string]$p.InvocationOperator -eq 'Ampersand' -and
    $p.CommandElements.Count -gt 0 -and [object]::ReferenceEquals($p.CommandElements[0], $sbe))
}
# Enclosing scope: function name (lower-cased; PowerShell resolves names
# case-insensitively, so the gate must too) or <script>, plus "/{}" per
# enclosing ISOLATED (`& { }`) script block.
function _scope($node) {
  $parts = @()
  $n = $node.Parent
  while ($n) {
    if ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
      $parts = @($n.Name.ToLowerInvariant()) + $parts
      break
    }
    if ($n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -and (_isIsolatedBlock $n)) {
      $parts = @('{}') + $parts
    }
    $n = $n.Parent
  }
  if (-not $parts -or $parts[0] -eq '{}') { $parts = @('<script>') + $parts }
  ($parts -join '/')
}
# Root variable of an expression ($a.b.c / $x[1] -> a / x); null when the root
# is not a variable (a type literal, a parenthesised command, a literal).
function _root($e) {
  while ($true) {
    if ($e -is [System.Management.Automation.Language.VariableExpressionAst]) { return (_varName $e) }
    if ($e -is [System.Management.Automation.Language.MemberExpressionAst]) { $e = $e.Expression; continue }
    if ($e -is [System.Management.Automation.Language.IndexExpressionAst]) { $e = $e.Target; continue }
    if ($e -is [System.Management.Automation.Language.ConvertExpressionAst]) { $e = $e.Child; continue }
    return $null
  }
}

# Exit statements directly in a block (not nested deeper).
function Get-BlockExits($Block) {
  if ($null -eq $Block) { return @() }
  $kinds = @()
  foreach ($s in $Block.Statements) {
    if ($s -is [System.Management.Automation.Language.ThrowStatementAst]) { $kinds += 'throw' }
    elseif ($s -is [System.Management.Automation.Language.ReturnStatementAst]) { $kinds += 'return' }
    elseif ($s -is [System.Management.Automation.Language.ExitStatementAst]) { $kinds += 'exit' }
    elseif ($s -is [System.Management.Automation.Language.BreakStatementAst]) { $kinds += 'break' }
    elseif ($s -is [System.Management.Automation.Language.ContinueStatementAst]) { $kinds += 'continue' }
  }
  return $kinds
}

# A statement that can stop execution before a later sibling runs: an `if`
# whose clause exits directly, an `Assert-*` call, or a bare exit statement.
function Get-GuardText($Statement) {
  if ($Statement -is [System.Management.Automation.Language.IfStatementAst]) {
    $parts = @()
    $exits = $false
    foreach ($clause in $Statement.Clauses) {
      $k = @(Get-BlockExits $clause.Item2)
      if ($k.Count -gt 0) { $exits = $true }
      $parts += ('({0}) -> {1}' -f (_flat $clause.Item1.Extent.Text), $(if ($k.Count) { $k -join ',' } else { '...' }))
    }
    if ($null -ne $Statement.ElseClause) {
      $k = @(Get-BlockExits $Statement.ElseClause)
      if ($k.Count -gt 0) { $exits = $true }
      $parts += ('else -> {0}' -f $(if ($k.Count) { $k -join ',' } else { '...' }))
    }
    if ($exits) { return 'guard if ' + ($parts -join ' | ') }
    return $null
  }
  if ($Statement -is [System.Management.Automation.Language.PipelineAst] -and $Statement.PipelineElements.Count -eq 1 -and
    $Statement.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
    $name = $Statement.PipelineElements[0].GetCommandName()
    if ($name -and $name -like 'Assert-*') { return 'guard ' + (_flat $Statement.Extent.Text) }
    return $null
  }
  foreach ($t in @('Throw', 'Return', 'Exit', 'Break', 'Continue')) {
    if ($Statement.GetType().Name -eq "${t}StatementAst") { return 'guard ' + (_flat $Statement.Extent.Text) }
  }
  return $null
}

# Control-flow context of a node, outermost first. Guard texts are cached per
# statement (keyed by node identity).
$GuardCache = @{}
function Get-NodeContext($Ast) {
  $levels = [System.Collections.Generic.List[string]]::new()
  $child = $Ast
  $parent = $Ast.Parent
  while ($null -ne $parent) {
    $here = [System.Collections.Generic.List[string]]::new()
    if ($parent -is [System.Management.Automation.Language.StatementBlockAst] -or
      $parent -is [System.Management.Automation.Language.NamedBlockAst]) {
      if ($parent -is [System.Management.Automation.Language.NamedBlockAst] -and -not $parent.Unnamed) {
        $here.Add("block $($parent.BlockKind)")
      }
      foreach ($s in $parent.Statements) {
        if ([object]::ReferenceEquals($s, $child)) { break }
        if (-not $GuardCache.ContainsKey($s)) { $GuardCache[$s] = Get-GuardText $s }
        $g = $GuardCache[$s]
        if ($g) { $here.Add($g) }
      }
    } elseif ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
      $conds = @()
      $placed = $false
      foreach ($clause in $parent.Clauses) {
        $c = _flat $clause.Item1.Extent.Text
        if ([object]::ReferenceEquals($clause.Item1, $child)) { $here.Add("if-condition after [$($conds -join ' ; ')]"); $placed = $true; break }
        if ([object]::ReferenceEquals($clause.Item2, $child)) { $here.Add("if ($c) after [$($conds -join ' ; ')]"); $placed = $true; break }
        $conds += "($c)"
      }
      if (-not $placed) { $here.Add("else of [$($conds -join ' ; ')]") }
    } elseif ($parent -is [System.Management.Automation.Language.ForEachStatementAst]) {
      $here.Add("foreach (`$$($parent.Variable.VariablePath.UserPath) in $(_flat $parent.Condition.Extent.Text))")
    } elseif ($parent -is [System.Management.Automation.Language.ForStatementAst]) {
      $here.Add("for ($(_flat $parent.Initializer.Extent.Text); $(_flat $parent.Condition.Extent.Text); $(_flat $parent.Iterator.Extent.Text))")
    } elseif ($parent -is [System.Management.Automation.Language.LoopStatementAst]) {
      $here.Add("$($parent.GetType().Name -replace 'StatementAst$', '') ($(_flat $parent.Condition.Extent.Text))")
    } elseif ($parent -is [System.Management.Automation.Language.SwitchStatementAst]) {
      $here.Add("switch ($(_flat $parent.Condition.Extent.Text))")
    } elseif ($parent -is [System.Management.Automation.Language.TryStatementAst]) {
      if ([object]::ReferenceEquals($parent.Body, $child)) { $here.Add('try') }
      elseif ([object]::ReferenceEquals($parent.Finally, $child)) { $here.Add('finally') }
    } elseif ($parent -is [System.Management.Automation.Language.CatchClauseAst]) {
      $here.Add('catch [' + (@($parent.CatchTypes | ForEach-Object { $_.TypeName.FullName }) -join ', ') + ']')
    } elseif ($parent -is [System.Management.Automation.Language.TrapStatementAst]) {
      $here.Add('trap')
    } elseif ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
      $here.Add("function $($parent.Name)")
    } elseif ($parent -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
      $owner = $parent.Parent
      if ($owner -is [System.Management.Automation.Language.CommandParameterAst]) {
        $here.Add("scriptblock -$($owner.ParameterName) of $($owner.Parent.GetCommandName())")
      } elseif ($owner -is [System.Management.Automation.Language.CommandAst]) {
        $here.Add("scriptblock of $($owner.GetCommandName())")
      } else {
        $here.Add("scriptblock in $($owner.GetType().Name)")
      }
    }
    for ($i = $here.Count - 1; $i -ge 0; $i--) { $levels.Insert(0, $here[$i]) }
    $child = $parent
    $parent = $parent.Parent
  }
  return , $levels.ToArray()
}

# Common parameters that write a variable named by their argument. Any
# parameter token that is a prefix of one of these (or ends in "variable") is
# treated as such a write, whatever command it is on.
$VARIABLE_COMMON = @('outvariable', 'errorvariable', 'warningvariable', 'informationvariable', 'pipelinevariable')
$VARIABLE_ALIASES = @('ov', 'ev', 'wv', 'iv', 'pv')
function _isVariableParam([string]$param) {
  if ($VARIABLE_ALIASES -contains $param -or $param.EndsWith('variable')) { return $true }
  return [bool](@($VARIABLE_COMMON | Where-Object { $_.StartsWith($param) }).Count)
}

function _paramList($fd) {
  if ($fd.Parameters) { return @($fd.Parameters) }
  if ($fd.Body.ParamBlock) { return @($fd.Body.ParamBlock.Parameters) }
  return @()
}

# Flatten an assignment's left side into its individual targets: casts and
# attributes are unwrapped, a parenthesised single expression is entered, and
# an array literal contributes each element. Returns AST nodes.
function _targetNodes($e) {
  while ($e -is [System.Management.Automation.Language.ConvertExpressionAst] -or
    $e -is [System.Management.Automation.Language.AttributedExpressionAst]) { $e = $e.Child }
  if ($e -is [System.Management.Automation.Language.ParenExpressionAst]) {
    $pipe = $e.Pipeline
    if ($pipe -is [System.Management.Automation.Language.PipelineAst] -and
      $pipe.PipelineElements.Count -eq 1 -and
      $pipe.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) {
      return @(_targetNodes $pipe.PipelineElements[0].Expression)
    }
    return @($e)
  }
  if ($e -is [System.Management.Automation.Language.ArrayLiteralAst]) {
    $out = @()
    foreach ($el in $e.Elements) { $out += @(_targetNodes $el) }
    return $out
  }
  return @($e)
}

function New-VarBinding($v, [string]$kind, [string]$target, [string]$value, $node) {
  [ordered]@{
    variable  = (_varName $v)
    qualifier = (_qualifier $v)
    drive     = (_drive $v)
    kind      = $kind
    target    = $target
    value     = $value
    scope     = (_scope $node)
  }
}

# SHA-256 of the script header: the source from the start of the file through
# the end of the script param block (comment-based help, [CmdletBinding], every
# parameter with its attributes and defaults), CRLF->LF. Hand-pinned by the gate.
function Get-HeaderDigest([string]$File, $Ast) {
  $text = ConvertTo-Lf ([System.IO.File]::ReadAllText($File).TrimStart([char]0xFEFF))
  $raw = [System.IO.File]::ReadAllText($File).TrimStart([char]0xFEFF)
  if ($null -eq $Ast.ParamBlock) { $end = 0 } else {
    $end = (ConvertTo-Lf $raw.Substring(0, $Ast.ParamBlock.Extent.EndOffset)).Length
  }
  $hash = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([System.BitConverter]::ToString($hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text.Substring(0, $end)))) -replace '-', '').ToLowerInvariant()
  } finally { $hash.Dispose() }
}

# Command-availability lookups are slow; cache them per process (shared across
# the files of a -Many run).
$CommandAvailable = @{}

function Get-Inventory([string]$File) {
  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$tokens, [ref]$parseErrors)
  $facts = Get-SourceFacts $File
  $rows = [System.Collections.Generic.List[object]]::new()
  $unsupported = [System.Collections.Generic.List[string]]::new()
  Add-AstRows -Node $ast -Depth 0 -Role 'Script' -Rows $rows -Unsupported $unsupported
  $parseErrorText = @($parseErrors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" })

  if ($AstOnly) {
    return [ordered]@{
      path          = $File
      source_sha256 = $facts[0]
      parse_errors  = $parseErrorText
      ast_rows      = $rows.ToArray()
    }
  }
  if ($Sites) {
    $significant = @($tokens | Where-Object {
        $_.Kind -notin @('NewLine', 'LineContinuation', 'Comment', 'EndOfInput')
      } | ForEach-Object {
        [ordered]@{ kind = [string]$_.Kind; start = $_.Extent.StartOffset; end = $_.Extent.EndOffset; text = $_.Text }
      })
    $siblings = @()
    foreach ($b in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StatementBlockAst] -or
          $n -is [System.Management.Automation.Language.NamedBlockAst] }, $true)) {
      $st = @($b.Statements)
      for ($i = 0; $i + 1 -lt $st.Count; $i++) {
        $siblings += , @($st[$i].Extent.StartOffset, $st[$i].Extent.EndOffset,
          $st[$i + 1].Extent.StartOffset, $st[$i + 1].Extent.EndOffset)
      }
    }
    $conditions = @()
    foreach ($n in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {
      foreach ($clause in $n.Clauses) {
        $conditions += , @($clause.Item1.Extent.StartOffset, $clause.Item1.Extent.EndOffset)
      }
    }
    $blockStarts = @()
    foreach ($fd in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
      $end = $fd.Body.EndBlock
      if ($null -ne $end -and $end.Statements.Count -gt 0) { $blockStarts += $end.Statements[0].Extent.StartOffset }
    }
    return [ordered]@{
      path = $File; tokens = $significant; siblings = $siblings; conditions = $conditions; block_starts = $blockStarts
    }
  }

  # One traversal, nodes grouped by concrete type (a FindAll per projection
  # invokes a scriptblock for every node, every time).
  $allNodes = @($ast.FindAll({ $true }, $true))
  $byType = @{}
  foreach ($n in $allNodes) {
    $tn = $n.GetType().Name
    if (-not $byType.ContainsKey($tn)) { $byType[$tn] = [System.Collections.Generic.List[object]]::new() }
    $byType[$tn].Add($n)
  }
  $nodes = {
    param([string[]]$names)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($nm in $names) { if ($byType.ContainsKey($nm)) { $out.AddRange($byType[$nm]) } }
    # restore source (pre-order) order across types
    @($out | Sort-Object { $_.Extent.StartOffset }, { -$_.Extent.EndOffset })
  }

  $functionDefs = & $nodes 'FunctionDefinitionAst'
  $functions = @($functionDefs | ForEach-Object { [ordered]@{ name = $_.Name; scope = (_scope $_) } })
  $functionParams = @()
  $paramsByFunction = @{}
  foreach ($fd in $functionDefs) {
    $params = @(_paramList $fd)
    $pipeline = @()
    foreach ($pa in $params) {
      foreach ($attr in $pa.Attributes) {
        if ($attr -is [System.Management.Automation.Language.AttributeAst]) {
          foreach ($na in $attr.NamedArguments) {
            if ($na.ArgumentName -like 'ValueFromPipeline*') { $pipeline += (_varName $pa.Name) }
          }
        }
      }
    }
    $names = @($params | ForEach-Object { _varName $_.Name })
    $paramsByFunction[$fd.Name.ToLowerInvariant()] = $names
    $functionParams += [ordered]@{ name = $fd.Name; params = $names; pipeline_params = @($pipeline | Sort-Object -Unique) }
  }

  $commands = @()
  $bindings = @()
  foreach ($c in (& $nodes 'CommandAst')) {
    $first = $c.CommandElements[0]
    $elements = @()
    $els = @($c.CommandElements | Select-Object -Skip 1)
    for ($i = 0; $i -lt $els.Count; $i++) {
      $e = $els[$i]
      $param = if ($e -is [System.Management.Automation.Language.CommandParameterAst]) { $e.ParameterName.ToLowerInvariant() } else { $null }
      $elements += [ordered]@{ kind = $e.GetType().Name; text = (_flat $e.Extent.Text); parameter = $param }
      if ($param -and (_isVariableParam $param)) {
        $target = if ($e.Argument) { $e.Argument.Extent.Text } elseif ($i + 1 -lt $els.Count) { $els[$i + 1].Extent.Text } else { '' }
        $bindings += [ordered]@{
          variable = ([string]$target).ToLowerInvariant(); qualifier = ''; drive = ''
          kind = 'common-parameter'; target = (_flat $target); value = "-$param"; scope = (_scope $c)
        }
      }
    }
    $name = $c.GetCommandName()
    # A call to a function defined in this file binds its parameters: one
    # "arg" binding per positional argument (an extra one binds $args) and per
    # named argument; a splatted variable may bind any parameter. The binding's
    # scope is the callee (where the parameter lives); target names the call site.
    if ($name -and $paramsByFunction.ContainsKey($name.ToLowerInvariant())) {
      $fparams = @($paramsByFunction[$name.ToLowerInvariant()])
      $explicit = @()
      $positional = @()
      for ($i = 0; $i -lt $els.Count; $i++) {
        $e = $els[$i]
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
          $pn = $e.ParameterName.ToLowerInvariant()
          $hit = @($fparams | Where-Object { $_ -eq $pn })
          if (-not $hit) { $hit = @($fparams | Where-Object { $_.StartsWith($pn) }) }
          $argText = if ($e.Argument) { $e.Argument.Extent.Text } elseif ($i + 1 -lt $els.Count -and
            -not ($els[$i + 1] -is [System.Management.Automation.Language.CommandParameterAst])) { $i++; $els[$i].Extent.Text } else { 'switch' }
          $bound = if ($hit.Count -eq 1) { $hit[0] } else { "-$pn" }
          $explicit += $bound
          $bindings += [ordered]@{ variable = $bound; qualifier = ''; drive = ''; kind = 'arg'; target = "$name @ $(_scope $c)"
            value = (_flat $argText); scope = $name.ToLowerInvariant() }
        } elseif ($e -is [System.Management.Automation.Language.VariableExpressionAst] -and $e.Splatted) {
          foreach ($fp in $fparams) {
            $bindings += [ordered]@{ variable = $fp; qualifier = ''; drive = ''; kind = 'splat'; target = "$name @ $(_scope $c)"
              value = (_flat $e.Extent.Text); scope = $name.ToLowerInvariant() }
          }
        } else {
          $positional += , $e
        }
      }
      $free = @($fparams | Where-Object { $explicit -notcontains $_ })
      for ($i = 0; $i -lt $positional.Count; $i++) {
        $bound = if ($i -lt $free.Count) { $free[$i] } else { 'args' }
        $bindings += [ordered]@{ variable = $bound; qualifier = ''; drive = ''; kind = 'arg'; target = "$name @ $(_scope $c)"
          value = (_flat $positional[$i].Extent.Text); scope = $name.ToLowerInvariant() }
      }
    }
    # Canonical parameter names from the real cmdlet metadata (resolves unique
    # prefixes such as -Pi and aliases such as -pv / -ov / -ev) when the command
    # is available to this pwsh; $null when it is not (e.g. Get-WmiObject or the
    # IIS cmdlets on Linux), in which case the gate falls back to its own strict
    # prefix/alias matching.
    $resolved = $null
    if ($name -and -not $paramsByFunction.ContainsKey($name.ToLowerInvariant())) {
      try {
        $key = $name.ToLowerInvariant()
        if (-not $CommandAvailable.ContainsKey($key)) {
          $CommandAvailable[$key] = [bool](Get-Command -Name $name -CommandType Cmdlet, Function -ErrorAction SilentlyContinue)
        }
        if ($CommandAvailable[$key]) {
          $binding = [System.Management.Automation.Language.StaticParameterBinder]::BindCommand($c, $true)
          if ($null -ne $binding) { $resolved = @($binding.BoundParameters.Keys | ForEach-Object { [string]$_ } | Sort-Object) }
        }
      } catch { $resolved = $null }
    }
    $commands += [ordered]@{
      name     = $name
      head     = (_flat $first.Extent.Text)
      bareword = ($first -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $first.StringConstantType -eq 'BareWord')
      operator = [string]$c.InvocationOperator
      args     = @($elements | ForEach-Object { $_.text })
      elements = $elements
      bound_params = $resolved
      scope    = (_scope $c)
      context  = (Get-NodeContext $c)
      text     = (_flat $c.Extent.Text)
    }
  }

  $members = @()
  foreach ($m in (& $nodes 'InvokeMemberExpressionAst', 'BaseCtorInvokeMemberExpressionAst')) {
    $members += [ordered]@{
      static          = [bool]$m.Static
      target          = (_flat $m.Expression.Extent.Text)
      receiver_root   = (_root $m.Expression)
      member          = (_flat $m.Member.Extent.Text)
      constant_member = ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst])
      argc            = @($m.Arguments).Count
      args            = @($m.Arguments | ForEach-Object { _flat $_.Extent.Text })
      scope           = (_scope $m)
      context         = (Get-NodeContext $m)
      text            = (_flat $m.Extent.Text)
    }
  }

  $redirections = @()
  foreach ($r in (& $nodes 'FileRedirectionAst', 'MergingRedirectionAst')) {
    $redirections += [ordered]@{
      kind     = $r.GetType().Name
      stream   = [string]$r.FromStream
      append   = if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) { [bool]$r.Append } else { $null }
      location = if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) { (_flat $r.Location.Extent.Text) } else { $null }
      scope    = (_scope $r)
      text     = (_flat $r.Extent.Text)
    }
  }

  $memberAssignments = @()
  foreach ($a in (& $nodes 'AssignmentStatementAst')) {
    $targets = @(_targetNodes $a.Left)
    # A single plain-variable target keeps the operator kind; several targets or a
    # parenthesised form is a destructuring binding (never a pinned form).
    $simple = ($targets.Count -eq 1 -and
      -not ($a.Left -is [System.Management.Automation.Language.ParenExpressionAst]) -and
      -not ($a.Left -is [System.Management.Automation.Language.ArrayLiteralAst]))
    foreach ($t in $targets) {
      if ($t -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $kind = if ($simple) { "assign $($a.Operator)" } else { "destructure $($a.Operator)" }
        $bindings += New-VarBinding $t $kind (_flat $a.Left.Extent.Text) (_flat $a.Right.Extent.Text) $a
      } elseif ($t -is [System.Management.Automation.Language.MemberExpressionAst] -or
        $t -is [System.Management.Automation.Language.IndexExpressionAst]) {
        $memberAssignments += [ordered]@{
          kind          = if ($t -is [System.Management.Automation.Language.IndexExpressionAst]) { 'index' } else { 'member' }
          receiver_root = (_root $t)
          target        = (_flat $t.Extent.Text)
          operator      = [string]$a.Operator
          value         = (_flat $a.Right.Extent.Text)
          scope         = (_scope $a)
        }
      } else {
        # Any other target shape is recorded so the checker rejects it.
        $bindings += [ordered]@{
          variable = $null; qualifier = ''; drive = ''; kind = 'assign-unrecognised-target'
          target = (_flat $t.Extent.Text); value = (_flat $a.Right.Extent.Text); scope = (_scope $a)
        }
      }
    }
  }
  # ++ / -- rebind their operand.
  foreach ($u in (& $nodes 'UnaryExpressionAst')) {
    if ([string]$u.TokenKind -notin @('PlusPlus', 'MinusMinus', 'PostfixPlusPlus', 'PostfixMinusMinus')) { continue }
    if ($u.Child -is [System.Management.Automation.Language.VariableExpressionAst]) {
      $bindings += New-VarBinding $u.Child "incdec $($u.TokenKind)" (_flat $u.Extent.Text) '' $u
    } else {
      $bindings += [ordered]@{
        variable = $null; qualifier = ''; drive = ''; kind = 'assign-unrecognised-target'
        target = (_flat $u.Extent.Text); value = ''; scope = (_scope $u)
      }
    }
  }
  # [ref]$x hands the variable to a callee that may write it.
  foreach ($r in @(& $nodes 'ConvertExpressionAst' | Where-Object {
        $_.Type.TypeName.FullName -in @('ref', 'System.Management.Automation.PSReference') })) {
    $owner = $r.Parent
    while ($null -ne $owner -and -not ($owner -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
      -not ($owner -is [System.Management.Automation.Language.CommandAst]) -and
      -not ($owner -is [System.Management.Automation.Language.StatementAst])) { $owner = $owner.Parent }
    if ($r.Child -is [System.Management.Automation.Language.VariableExpressionAst]) {
      $bindings += New-VarBinding $r.Child 'ref' (_flat $r.Extent.Text) $(if ($owner) { _flat $owner.Extent.Text } else { '' }) $r
    } else {
      $bindings += [ordered]@{
        variable = $null; qualifier = ''; drive = ''; kind = 'assign-unrecognised-target'
        target = (_flat $r.Extent.Text); value = ''; scope = (_scope $r)
      }
    }
  }
  foreach ($f in (& $nodes 'ForEachStatementAst')) {
    $bindings += New-VarBinding $f.Variable 'foreach' (_flat $f.Variable.Extent.Text) (_flat $f.Condition.Extent.Text) $f
  }
  foreach ($p in (& $nodes 'ParameterAst')) {
    # Function parameters, param() blocks of the script, functions and script
    # blocks. The value is the whole declaration (attributes, type, default).
    $bindings += New-VarBinding $p.Name 'parameter' (_flat $p.Extent.Text) (_flat $p.Extent.Text) $p
  }

  $variableRefs = @()
  $seen = @{}
  foreach ($v in (& $nodes 'VariableExpressionAst')) {
    $key = "$($v.VariablePath.UserPath)|$($v.Splatted)"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $variableRefs += [ordered]@{
      name = (_varName $v); qualifier = (_qualifier $v); drive = (_drive $v); splatted = [bool]$v.Splatted
      text = $v.Extent.Text
    }
  }

  # Every variable reference (not deduplicated), with its scope and the text of
  # the innermost enclosing statement: the secret-taint table pins where each
  # credential-bearing variable may appear.
  $variableUses = @()
  foreach ($v in (& $nodes 'VariableExpressionAst')) {
    $st = $v.Parent
    while ($null -ne $st -and -not ($st -is [System.Management.Automation.Language.StatementAst] -and
        -not ($st -is [System.Management.Automation.Language.CommandBaseAst]))) { $st = $st.Parent }
    $variableUses += [ordered]@{
      name = (_varName $v); scope = (_scope $v)
      statement = $(if ($st) { _flat $st.Extent.Text } else { '' })
    }
  }
  # Every branch / loop condition: its variables are binding-pinned.
  $conditions = @()
  foreach ($n in (& $nodes 'IfStatementAst')) {
    foreach ($clause in $n.Clauses) { $conditions += [ordered]@{ scope = (_scope $n); text = (_flat $clause.Item1.Extent.Text) } }
  }
  foreach ($n in (& $nodes 'ForStatementAst', 'ForEachStatementAst', 'WhileStatementAst', 'DoWhileStatementAst',
      'DoUntilStatementAst', 'SwitchStatementAst')) {
    if ($null -ne $n.Condition) { $conditions += [ordered]@{ scope = (_scope $n); text = (_flat $n.Condition.Extent.Text) } }
  }

  $types = @(& $nodes 'TypeExpressionAst', 'TypeConstraintAst', 'ConvertExpressionAst' | ForEach-Object {
      if ($_ -is [System.Management.Automation.Language.ConvertExpressionAst]) { $_.Type.TypeName.FullName }
      else { $_.TypeName.FullName }
    } | Sort-Object -Unique)

  [ordered]@{
    path                   = $File
    parse_errors           = $parseErrorText
    source_sha256          = $facts[0]
    source_non_ascii_bytes = $facts[1]
    ast_rows               = $rows.ToArray()
    unsupported_nodes      = @($unsupported | Sort-Object -Unique)
    node_types             = @($byType.Keys | Sort-Object -Unique)
    script_requirements    = ($null -ne $ast.ScriptRequirements)
    background_pipelines   = @(& $nodes 'PipelineAst', 'PipelineChainAst' | Where-Object { $_.Background } |
        ForEach-Object { _flat $_.Extent.Text })
    foreach_flags          = @(& $nodes 'ForEachStatementAst' |
        ForEach-Object { [string]$_.Flags } | Sort-Object -Unique)
    commands               = $commands
    members                = $members
    redirections           = $redirections
    bindings               = $bindings
    member_assignments     = $memberAssignments
    functions              = $functions
    function_params        = $functionParams
    variable_refs          = $variableRefs
    variable_uses          = $variableUses
    header_sha256          = (Get-HeaderDigest $File $ast)
    conditions             = $conditions
    static_types           = $types
  }
}

function Get-SwappedSource([string]$File) {
  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$tokens, [ref]$parseErrors)
  $text = [System.IO.File]::ReadAllText($File)
  # (startOffset, length) spans of NAMES to case-flip.
  $spans = [System.Collections.Generic.List[object]]::new()
  function Add-Span([int]$Start, [int]$Length) {
    $spans.Add([pscustomobject]@{ Start = $Start; Len = $Length })
  }
  foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $e0 = $c.CommandElements[0]
    if ($e0 -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
      Add-Span $e0.Extent.StartOffset ($e0.Extent.EndOffset - $e0.Extent.StartOffset)
    }
  }
  foreach ($p in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandParameterAst] }, $true)) {
    # Only the "-Name" portion; any :value follows the name.
    Add-Span $p.Extent.StartOffset (1 + $p.ParameterName.Length)
  }
  foreach ($v in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    Add-Span $v.Extent.StartOffset ($v.Extent.EndOffset - $v.Extent.StartOffset)
  }
  foreach ($span in ($spans | Sort-Object Start -Descending)) {
    $start = $span.Start; $len = $span.Len
    $piece = $text.Substring($start, $len)
    # swapcase, preserving non-letters ($ { } : -).
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $piece.ToCharArray()) {
      if ([char]::IsUpper($ch)) { [void]$sb.Append([char]::ToLower($ch)) }
      elseif ([char]::IsLower($ch)) { [void]$sb.Append([char]::ToUpper($ch)) }
      else { [void]$sb.Append($ch) }
    }
    $text = $text.Substring(0, $start) + $sb.ToString() + $text.Substring($start + $len)
  }
  return $text
}

if ($SwapNames) {
  $out = @()
  foreach ($file in $Path) {
    $resolved = (Resolve-Path -LiteralPath $file).Path
    $out += , ([ordered]@{ path = $resolved; swapped = (Get-SwappedSource $resolved) })
  }
  ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
} elseif ($Many) {
  $out = @()
  foreach ($file in $Path) { $out += , (Get-Inventory (Resolve-Path -LiteralPath $file).Path) }
  ConvertTo-Json -InputObject @($out) -Depth 12 -Compress
} else {
  if (@($Path).Count -ne 1) { throw 'exactly one -Path is required without -Many' }
  Get-Inventory (Resolve-Path -LiteralPath $Path[0]).Path | ConvertTo-Json -Depth 12 -Compress
}
