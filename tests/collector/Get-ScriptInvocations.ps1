<#
  PARSE (never execute) a PowerShell script and emit, as JSON, every command
  invocation, .NET member invocation, New-Object type, and function definition
  in it. Consumed by tests/test_collector_readonly.py, which enforces an
  allowlist over the result. Uses [Parser]::ParseFile only: nothing in the
  target script runs, so this is safe on a script that talks to AD / WMI.
#>
param([Parameter(Mandatory)] [string] $Path)

$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path $Path).Path, [ref]$tokens, [ref]$parseErrors)

function _flat([string]$s) { ($s -replace '\s+', ' ').Trim() }

$commands = @()
foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
  $first = $c.CommandElements[0]
  $commands += [ordered]@{
    # Null when the command name is computed at runtime (& $x, & (expr)).
    name     = $c.GetCommandName()
    bareword = ($first -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $first.StringConstantType -eq 'BareWord')
    operator = [string]$c.InvocationOperator
    args     = @($c.CommandElements | Select-Object -Skip 1 | ForEach-Object { _flat $_.Extent.Text })
    text     = (_flat $c.Extent.Text)
    line     = $c.Extent.StartLineNumber
  }
}

$members = @()
foreach ($m in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
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

$functions = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
  ForEach-Object { $_.Name })

$staticTypes = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeExpressionAst] }, $true) |
  ForEach-Object { $_.TypeName.FullName } | Sort-Object -Unique)

[ordered]@{
  parse_errors = @($parseErrors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" })
  commands     = $commands
  members      = $members
  functions    = $functions
  static_types = $staticTypes
} | ConvertTo-Json -Depth 6
