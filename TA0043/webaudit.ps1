


$HeaderRules = @(
    @{
        Name           = "Server"
        Policy         = "NotRecommended"
        # Insecure if the header exists at all (is not null)
        IsInsecure     = { $null -ne $args[0] } 
        Recommendation = "Disable or mask this header in the server configuration to prevent fingerprinting."
    },
    @{
        Name           = "X-XSS-Protection"
        Policy         = "Required"
        # Insecure if it's missing OR if it doesn't start with '1'
        IsInsecure     = { $null -eq $args[0] -or $args[0] -notmatch '^1' } 
        Recommendation = "Enable in the server options (e.g., '1; mode=block') to protect older browsers against XSS attacks."
    },
    @{
        Name           = "Content-Security-Policy"
        Policy         = "Required"
        # Advanced logic: Insecure if missing or contains unsafe-inline without nonces
        IsInsecure     = { 
            $null -eq $args[0] -or ($args[0] -match "'unsafe-inline'" -and $args[0] -notmatch "'nonce-") 
        }
        Recommendation = "Implement a strong CSP. Avoid 'unsafe-inline' without nonces/hashes where possible."
    }
)

# Simulating a web response header dictionary
$ResponseHeaders = @{
    "Server"             = "Apache/2.4.41 (Ubuntu)"
    "X-XSS-Protection"   = "0" # Insecure value
    "X-Frame-Options"    = "DENY"
    # Content-Security-Policy and others are missing entirely
}

$Report = foreach ($Rule in $HeaderRules) {
    $HeaderValue = $ResponseHeaders[$Rule.Name]
    
    # Execute the ScriptBlock dynamically using the inside-out operator (&)
    $IsHeaderInsecure = Invoke-Command -ScriptBlock $Rule.IsInsecure -ArgumentList $HeaderValue

    [PSCustomObject]@{
        Header         = $Rule.Name
        Policy         = $Rule.Policy
        CurrentValue   = if ($null -eq $HeaderValue) { "[MISSING]" } else { $HeaderValue }
        Status         = if ($IsHeaderInsecure) { "FAIL" } else { "PASS" }
        Recommendation = if ($IsHeaderInsecure) { $Rule.Recommendation } else { "N/A" }
    }
}

# Displaying the results beautifully in the console
$Report | Format-Table -AutoSize