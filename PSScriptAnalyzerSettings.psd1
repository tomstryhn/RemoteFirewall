@{
    IncludeDefaultRules = $true

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }

        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework',
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
            )
            # Should, It, Invoke-Pester and InModuleScope are Pester's own DSL surface: Pester
            # adds parameters to them dynamically at import time (Should in particular), so the
            # static compatibility profiles, captured against a different Pester version, report
            # parameters such as Should -Be, Invoke-Pester -Configuration or InModuleScope
            # -Parameters as unavailable even though the Pester version this repository targets
            # (6.1.0) has them. Ignored here rather than disabling the rule outright.
            IgnoreCommands = @('Should', 'It', 'Invoke-Pester', 'InModuleScope')
        }

        PSAvoidUsingWriteHost = @{
            Enable = $true
        }
    }
}
