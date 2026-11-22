param(
    [switch]$SkipCloudBase
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$message = Read-Host "更新说明（留空自动生成）"
if ([string]::IsNullOrWhiteSpace($message)) {
    $message = "update " + (Get-Date -Format "yyyy-MM-dd HH:mm")
}

git add -A
$pending = git status --porcelain
if ([string]::IsNullOrWhiteSpace($pending)) {
    Write-Host "没有需要提交的文件改动。" -ForegroundColor Yellow
} else {
    git commit -m $message
    git push origin main
    Write-Host "GitHub 已更新，GitHub Pages 会自动重新发布。" -ForegroundColor Green
}

if (-not $SkipCloudBase) {
    $answer = Read-Host "是否同步重新部署 CloudBase？后端改动或使用 CloudBase 直连时需要 y (y/N)"
    if ($answer -match "^[Yy]") {
        tcb cloudrun deploy `
            -e gastric-skunk-d1gn1l6iv2cfab3e2 `
            -s lab-ms `
            --port 80 `
            --source . `
            --force --yes --wait
        Write-Host "CloudBase 部署完成。" -ForegroundColor Green
        Write-Host "注意：SQLite 位于 /tmp/lab.db，重新部署可能重置数据。" -ForegroundColor Yellow
    } else {
        Write-Host "已跳过 CloudBase 部署。" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "完成。GitHub Pages 地址："
Write-Host "https://lsbdanko.github.io/lab-ms1.0.2/"
