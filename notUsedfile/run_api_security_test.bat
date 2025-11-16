@echo off
echo ---------------------------------------------
echo   Running API Security Test (Swagger Runner)
echo ---------------------------------------------
echo.

REM Activate Python if needed (optional)
REM call C:\Path\To\Python\Scripts\activate.bat

python swagger_api_runner.py ^
  --login-url "https://fxnfekhq3ld22z5a3q4htarzz40wmxir.lambda-url.ap-south-1.on.aws/swagger/login" ^
  --login-payload "{\"username\":\"+910014082016\",\"password\":\"ssba123\",\"service\":\"ITR\"}" ^
  --config-url "https://dev-api.taxbuddy.com/itr/swagger/config" ^
  --do-fuzz

echo.
echo ---------------------------------------------
echo   Script Completed. Check Reports:
echo       - api_report.html
echo       - api_report.csv
echo ---------------------------------------------
pause
