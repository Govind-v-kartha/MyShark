param(
    [ValidateSet('run','test','lint')]
    [string]$task = 'run'
)

switch ($task) {
  'run' {
    uvicorn web_app:app --host 127.0.0.1 --port 8000 --reload
  }
  'test' {
    pytest -q -rA
  }
  'lint' {
    ruff check .
  }
}
