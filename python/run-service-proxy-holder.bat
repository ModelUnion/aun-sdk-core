@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%.."

if not defined PYTHON set "PYTHON=python"

if not defined AUN_PROXY_ENV_FILE (
  if exist "%SCRIPT_DIR%.env" (
    set "AUN_PROXY_ENV_FILE=%SCRIPT_DIR%.env"
  ) else if exist "%REPO_ROOT%\.env" (
    set "AUN_PROXY_ENV_FILE=%REPO_ROOT%\.env"
  ) else (
    set "AUN_PROXY_ENV_FILE=.env"
  )
)

set "PYTHONPATH=%SCRIPT_DIR%src;%PYTHONPATH%"

pushd "%SCRIPT_DIR%" >nul
echo [service-proxy-holder] env=%AUN_PROXY_ENV_FILE%
echo [service-proxy-holder] args=%*
"%PYTHON%" -m aun_core.service_proxy.tools.test_service_holder --env-file "%AUN_PROXY_ENV_FILE%" %*
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul

exit /b %EXIT_CODE%
