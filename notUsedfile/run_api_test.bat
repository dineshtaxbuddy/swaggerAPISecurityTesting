@echo off
setlocal

REM Prompt for token (won't echo)
echo Enter Bearer token (just the token part, without 'Bearer '):
set /p USER_TOKEN=

REM Optionally set path-values file if you have one
REM set PATH_VALUES=path_values.json

python openapi_runner.py --config-url "https://dev-api.taxbuddy.com/pdf/swagger/config" --token "%USER_TOKEN%" --path-values "%PATH_VALUES%"

echo.
echo Reports written to .\results\api_results.csv and .\results\api_report.html
pause
endlocal
