```shell
# GIT CMD
curl -X POST http://localhost:8080/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic b2lkYy1jbGllbnQ6c2VjcmV0" \
     --data "grant_type=password&scope=openid profile&username=user&password=password"

# Power Shell
$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "Authorization" = "Basic b2lkYy1jbGllbnQ6c2VjcmV0"
}

$body = "grant_type=password&scope=openid profile&username=user&password=password"

Invoke-WebRequest -Uri "http://localhost:8080/oauth2/token" -Method POST -Headers $headers -Body $body
```