<#
  PARSE (never execute) a PowerShell script and emit, as JSON, everything the
  closed-world read-only gate (tests/test_collector_readonly.py) reasons about.
  Every entry carries its enclosing scope ("<script>" or the function name,
  plus "/{}" for each enclosing script block) and no line numbers, so the
  committed golden inventory changes only when the code does.

  Variable names are normalised to lower case WITHOUT their scope/drive prefix
  ($script:OutPath -> outpath): PowerShell resolves variable names
  case-insensitively, so the gate must too.

  Uses [Parser]::ParseFile only: nothing in the target script runs.
#>
param([Parameter(Mandatory)] [string] $Path)

$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path $Path).Path, [ref]$tokens, [ref]$parseErrors)
$L = [System.Management.Automation.Language.ScriptBlockAst].Assembly

function _flat([string]$s) { ($s -replace '\s+', ' ').Trim() }
function _find([scriptblock]$pred) { @($ast.FindAll($pred, $true)) }
function _varName($v) { ([string]$v.VariablePath.UserPath -split ':')[-1].ToLowerInvariant() }
# Enclosing scope: function name (or <script>) plus "/{}" per nested script block.
function _scope($node) {
  $parts = @()
  $n = $node.Parent
  while ($n) {
    if ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
      $parts = @($n.Name) + $parts
      break
    }
    if ($n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $parts = @('{}') + $parts }
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

# Common parameters that write a variable named by their argument.
$VARIABLE_COMMON = @('outvariable', 'ov', 'errorvariable', 'ev', 'warningvariable', 'wv',
                     'informationvariable', 'iv', 'pipelinevariable', 'pv')

$commands = @()
$bindings = @()
foreach ($c in (_find { $args[0] -is [System.Management.Automation.Language.CommandAst] })) {
  $first = $c.CommandElements[0]
  $elements = @()
  $els = @($c.CommandElements | Select-Object -Skip 1)
  for ($i = 0; $i -lt $els.Count; $i++) {
    $e = $els[$i]
    $param = if ($e -is [System.Management.Automation.Language.CommandParameterAst]) { $e.ParameterName.ToLowerInvariant() } else { $null }
    $elements += [ordered]@{ kind = $e.GetType().Name; text = (_flat $e.Extent.Text); parameter = $param }
    if ($param) {
      # A unique prefix of a -*Variable common parameter also binds it.
      $hit = @($VARIABLE_COMMON | Where-Object { $_.StartsWith($param) -and $param.Length -ge 2 })
      if ($hit) {
        $target = if ($e.Argument) { $e.Argument.Extent.Text } elseif ($i + 1 -lt $els.Count) { $els[$i + 1].Extent.Text } else { '' }
        $bindings += [ordered]@{
          variable = ($target.Trim("'", '"', '$') -split ':')[-1].ToLowerInvariant()
          kind = 'common-parameter'; value = "-$param"; scope = (_scope $c)
        }
      }
    }
  }
  $commands += [ordered]@{
    name     = $c.GetCommandName()
    bareword = ($first -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $first.StringConstantType -eq 'BareWord')
    operator = [string]$c.InvocationOperator
    args     = @($elements | ForEach-Object { $_.text })
    elements = $elements
    scope    = (_scope $c)
    text     = (_flat $c.Extent.Text)
  }
}

$members = @()
foreach ($m in (_find { $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] })) {
  $members += [ordered]@{
    static  = [bool]$m.Static
    target  = (_flat $m.Expression.Extent.Text)
    receiver_root = (_root $m.Expression)
    member  = (_flat $m.Member.Extent.Text)
    constant_member = ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst])
    argc    = @($m.Arguments).Count
    args    = @($m.Arguments | ForEach-Object { _flat $_.Extent.Text })
    scope   = (_scope $m)
    text    = (_flat $m.Extent.Text)
  }
}

$redirections = @()
foreach ($r in (_find { $args[0] -is [System.Management.Automation.Language.RedirectionAst] })) {
  $redirections += [ordered]@{
    kind     = $r.GetType().Name
    stream   = [string]$r.FromStream
    append   = if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) { [bool]$r.Append } else { $null }
    location = if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) { (_flat $r.Location.Extent.Text) } else { $null }
    scope    = (_scope $r)
    text     = (_flat $r.Extent.Text)
  }
}

foreach ($a in (_find { $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] })) {
  $left = $a.Left
  while ($left -is [System.Management.Automation.Language.ConvertExpressionAst] -or
         $left -is [System.Management.Automation.Language.AttributedExpressionAst]) { $left = $left.Child }
  $bindings += [ordered]@{
    # Null when the target is not a plain variable ($x.Prop = 1, $h['k'] = 1).
    variable = if ($left -is [System.Management.Automation.Language.VariableExpressionAst]) { _varName $left } else { $null }
    kind     = "assign $($a.Operator)"
    target   = (_flat $a.Left.Extent.Text)
    value    = (_flat $a.Right.Extent.Text)
    scope    = (_scope $a)
  }
}
foreach ($f in (_find { $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] })) {
  $bindings += [ordered]@{
    variable = (_varName $f.Variable); kind = 'foreach'; target = (_flat $f.Variable.Extent.Text)
    value = (_flat $f.Condition.Extent.Text); scope = (_scope $f)
  }
}
foreach ($p in (_find { $args[0] -is [System.Management.Automation.Language.ParameterAst] })) {
  # Function parameters, param() blocks of the script, functions and script blocks.
  $bindings += [ordered]@{
    variable = (_varName $p.Name); kind = 'parameter'; target = (_flat $p.Extent.Text)
    value = ''; scope = (_scope $p)
  }
}

$functions = @(_find { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] } |
  ForEach-Object { [ordered]@{ name = $_.Name; scope = (_scope $_) } })

$types = @(_find {
    $args[0] -is [System.Management.Automation.Language.TypeExpressionAst] -or
    $args[0] -is [System.Management.Automation.Language.TypeConstraintAst] -or
    $args[0] -is [System.Management.Automation.Language.ConvertExpressionAst]
  } | ForEach-Object {
    if ($_ -is [System.Management.Automation.Language.ConvertExpressionAst]) { $_.Type.TypeName.FullName }
    else { $_.TypeName.FullName }
  } | Sort-Object -Unique)

[ordered]@{
  parse_errors = @($parseErrors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" })
  commands     = $commands
  members      = $members
  redirections = $redirections
  bindings     = $bindings
  functions    = $functions
  static_types = $types
} | ConvertTo-Json -Depth 8
