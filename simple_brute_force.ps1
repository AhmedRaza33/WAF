# Simple Brute Force Attack Simulator for WAF Testing
# This script simulates a brute force login attack to test WAF detection

param(
    [string]$TargetUrl = "http://127.0.0.1:5000/login",
    [int]$DelayMs = 100,
    [int]$MaxAttempts = 20,
    [string]$UserAgent = "attack-bot"
)

Write-Host "Starting Brute Force Attack Simulation" -ForegroundColor Red
Write-Host "Target: $TargetUrl" -ForegroundColor Yellow
Write-Host "Max Attempts: $MaxAttempts" -ForegroundColor Yellow
Write-Host "Delay: $DelayMs ms between requests" -ForegroundColor Yellow
Write-Host "User-Agent: $UserAgent" -ForegroundColor Yellow
Write-Host ""

# Common username/password combinations for testing
$credentials = @(
    @{username="admin"; password="admin"},
    @{username="admin"; password="password"},
    @{username="admin"; password="123456"},
    @{username="admin"; password="admin123"},
    @{username="root"; password="root"},
    @{username="root"; password="password"},
    @{username="user"; password="user"},
    @{username="user"; password="password"},
    @{username="test"; password="test"},
    @{username="guest"; password="guest"},
    @{username="admin"; password="qwerty"},
    @{username="admin"; password="letmein"},
    @{username="admin"; password="welcome"},
    @{username="admin"; password="monkey"},
    @{username="admin"; password="dragon"},
    @{username="admin"; password="master"},
    @{username="admin"; password="shadow"},
    @{username="admin"; password="superman"},
    @{username="admin"; password="batman"},
    @{username="admin"; password="spider"}
)

$attemptCount = 0
$successCount = 0
$blockedCount = 0
$errorCount = 0

# Headers for the attack
$headers = @{
    "User-Agent" = $UserAgent
    "Content-Type" = "application/x-www-form-urlencoded"
    "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    "Accept-Language" = "en-US,en;q=0.5"
    "Accept-Encoding" = "gzip, deflate"
    "Connection" = "keep-alive"
    "Upgrade-Insecure-Requests" = "1"
}

Write-Host "Starting attack sequence..." -ForegroundColor Cyan

for ($i = 0; $i -lt $MaxAttempts; $i++) {
    $attemptCount++
    
    # Select a credential combination (cycle through the list)
    $credIndex = $i % $credentials.Length
    $username = $credentials[$credIndex].username
    $password = $credentials[$credIndex].password
    
    # Prepare the POST data using string concatenation to avoid syntax issues
    $body = "username=" + $username + "&password=" + $password
    
    try {
        Write-Host "Attempt $attemptCount : $username / $password" -ForegroundColor Gray
        
        # Send the POST request
        $response = Invoke-WebRequest -Uri $TargetUrl -Method POST -Headers $headers -Body $body -TimeoutSec 5
        
        $statusCode = $response.StatusCode
        
        if ($statusCode -eq 200) {
            Write-Host "SUCCESS! Status: $statusCode" -ForegroundColor Green
            $successCount++
        } elseif ($statusCode -eq 403) {
            Write-Host "BLOCKED! Status: $statusCode (WAF detected attack)" -ForegroundColor Red
            $blockedCount++
        } else {
            Write-Host "Unexpected Status: $statusCode" -ForegroundColor Yellow
        }
        
    } catch {
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -like "*403*") {
            Write-Host "BLOCKED! 403 Forbidden (WAF detected attack)" -ForegroundColor Red
            $blockedCount++
        } elseif ($errorMessage -like "*404*") {
            Write-Host "404 Not Found (Endpoint not available)" -ForegroundColor Yellow
        } elseif ($errorMessage -like "*timeout*") {
            Write-Host "Timeout (Request took too long)" -ForegroundColor Yellow
        } else {
            Write-Host "Error: $errorMessage" -ForegroundColor Red
        }
        
        $errorCount++
    }
    
    # Add delay between requests
    if ($DelayMs -gt 0) {
        Start-Sleep -Milliseconds $DelayMs
    }
    
    # Progress indicator
    if ($attemptCount % 5 -eq 0) {
        Write-Host "Progress: $attemptCount/$MaxAttempts attempts completed" -ForegroundColor Cyan
    }
}

# Summary
Write-Host ""
Write-Host "ATTACK SUMMARY" -ForegroundColor Magenta
Write-Host "==============" -ForegroundColor Magenta
Write-Host "Total Attempts: $attemptCount" -ForegroundColor White
Write-Host "Successful Logins: $successCount" -ForegroundColor Green
Write-Host "Blocked by WAF: $blockedCount" -ForegroundColor Red
Write-Host "Errors/Timeouts: $errorCount" -ForegroundColor Yellow
Write-Host ""

if ($blockedCount -gt 0) {
    Write-Host "WAF is working! It blocked $blockedCount attack attempts." -ForegroundColor Green
} else {
    Write-Host "WAF may not be detecting brute force attacks effectively." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Check your WAF logs for detailed information about the attack detection." -ForegroundColor Cyan 