<#
  PARSE (never execute) a PowerShell script and emit, as JSON, everything the
  read-only allowlist in tests/test_collector_readonly.py reasons about:
  command invocations (with their parameter tokens and argument kinds), .NET
  member invocations, redirections, variable assignments (any scope, compound
  operators, foreach loop variables), parameters, function definitions, and
  every type literal / conversion / constraint. Uses [Parser]::ParseFile only:
  nothing in the target script runs, so this is safe on a script that talks to
  AD / WMI.
#>
param([Parameter(Mandatory)] [string] $Path)

$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path $Path).Path, [ref]$tokens, [ref]$parseErrors)

function _flat([string]$s) { ($s -replace '\s+', ' ').Trim() }
function _find([scriptblock]$pred) { @($ast.FindAll($pred, $true)) }
# Variable name without its scope/drive qualifier: $script:p -> p.
function _varName($v) { ([string]$v.VariablePath.UserPath -split ':')[-1] }

$commands = @()
foreach ($c in (_find { $args[0] -is [System.Management.Automation.Language.CommandAst] })) {
  $first = $c.CommandElements[0]
  $elements = @()
  foreach ($e in @($c.CommandElements | Select-Object -Skip 1)) {
    $elements += [ordered]@{
      kind = $e.GetType().Name
      text = (_flat $e.Extent.Text)
      # For a CommandParameterAst: the parameter name without the dash.
      parameter = if ($e -is [System.Management.Automation.Language.CommandParameterAst]) { $e.ParameterName } else { $null }
    }
  }
  $commands += [ordered]@{
    # Null when the command name is computed at runtime (& $x, & (expr)).
    name     = $c.GetCommandName()
    bareword = ($first -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $first.StringConstantType -eq 'BareWord')
    operator = [string]$c.InvocationOperator
    args     = @($elements | ForEach-Object { $_.text })
    elements = $elements
    text     = (_flat $c.Extent.Text)
    line     = $c.Extent.StartLineNumber
  }
}

$members = @()
foreach ($m in (_find { $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] })) {
  $members += [ordered]@{
    static  = [bool]$m.Static
    target  = (_flat $m.Expression.Extent.Text)
    # Non-constant member names ($x.$name()) come through as their expression text.
    member  = (_flat $m.Member.Extent.Text)
    constant_member = ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst])
    argc    = @($m.Arguments).Count
    args    = @($m.Arguments | ForEach-Object { _flat $_.Extent.Text })
    text    = (_flat $m.Extent.Text)
    line    = $m.Extent.StartLineNumber
  }
}

$redirections = @()
foreach ($r in (_find { $args[0] -is [System.Management.Automation.Language.RedirectionAst] })) {
  $redirections += [ordered]@{
    kind     = $r.GetType().Name
    stream   = [string]$r.FromStream
    append   = if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) { [bool]$r.Append } else { $null }
    location = if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) { (_flat $r.Location.Extent.Text) } else { $null }
    text     = (_flat $r.Extent.Text)
    line     = $r.Extent.StartLineNumber
  }
}

$assignments = @()
foreach ($a in (_find { $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] })) {
  $left = $a.Left
  while ($left -is [System.Management.Automation.Language.ConvertExpressionAst] -or
         $left -is [System.Management.Automation.Language.AttributedExpressionAst]) { $left = $left.Child }
  $assignments += [ordered]@{
    # Null when the target is not a plain variable (e.g. $x.Prop = 1, $h['k'] = 1).
    variable = if ($left -is [System.Management.Automation.Language.VariableExpressionAst]) { _varName $left } else { $null }
    target   = (_flat $a.Left.Extent.Text)
    operator = [string]$a.Operator
    value    = (_flat $a.Right.Extent.Text)
    line     = $a.Extent.StartLineNumber
  }
}
foreach ($f in (_find { $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] })) {
  $assignments += [ordered]@{
    variable = (_varName $f.Variable); target = (_flat $f.Variable.Extent.Text)
    operator = 'foreach'; value = (_flat $f.Condition.Extent.Text); line = $f.Extent.StartLineNumber
  }
}

$parameters = @(_find { $args[0] -is [System.Management.Automation.Language.ParameterAst] } |
  ForEach-Object { _varName $_.Name })

$functions = @(_find { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] } |
  ForEach-Object { $_.Name })

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
  assignments  = $assignments
  parameters   = $parameters
  functions    = $functions
  static_types = $types
} | ConvertTo-Json -Depth 8
