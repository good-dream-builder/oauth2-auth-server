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


```shell
http://localhost:8080/oauth2/authorize?response_type=code&client_id=oidc-client&redirect_uri=http://127.0.0.1:3000/login/oauth2/code/oidc-client&scope=openid%20profile
```

```text
http://127.0.0.1:3000/login/oauth2/code/oidc-client?code=7N_sq_ozCd2WUxCa4oTt5ESJNqUHgFKgErkTNrQMGgGe0HQBiO56YjbqZlhLysZ_s-i9a9LsH3DwyovMb_ippe7N-lG4CE5CAqxj_Q0Fs-L5jEvZk3CSWfYz2_OY5dkr```
```


```shell
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'oidc-client:secret' | base64)" \
  -d "grant_type=authorization_code&code=<AUTHORIZATION_CODE>&redirect_uri=http://127.0.0.1:3000/login/oauth2/code/oidc-client"
```


```shell
curl -X POST http://localhost:8080/oauth2/token \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Authorization: Basic $(echo -n 'oidc-client:secret' | base64)" \
-d "grant_type=authorization_code&code=7N_sq_ozCd2WUxCa4oTt5ESJNqUHgFKgErkTNrQMGgGe0HQBiO56YjbqZlhLysZ_s-i9a9LsH3DwyovMb_ippe7N-lG4CE5CAqxj_Q0Fs-L5jEvZk3CSWfYz2_OY5dkr&redirect_uri=http://127.0.0.1:3000/login/oauth2/code/oidc-client"

```


```json
{
    "access_token": "eyJraWQiOiJjMmRlMTFlMy0zNmViLTQ3NzUtYWRhZi1mMzczNjE1ZDIwZTQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJuYmYiOjE3MjQzMzk1ODUsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNzI0MzM5ODg1LCJpYXQiOjE3MjQzMzk1ODUsImp0aSI6IjgxMjQwMGNkLTcwMTgtNDdhNS1hMjM5LTAwZTRmOTBjNThjNyJ9.P5QQrzTeM1MgoLPSkLWv6sjVZdgnVh5YR0eODAzNyqSgOZ1dVfX91HDmS7HBEhG-meT0SEfREFUbLwq33Vc5U5FTdx56FLckVEPLw39FMqtMCIt-OFD_8ChA4IMHkUctM55sYjl_4fwaTTUvv74lHgqeCuLG9ixZDPrAvw1A0YosHrFuNnyuasff2J5kuR2uYENKnP7Un8iyaF21ZDj-PXHgpthWZB-rCXrkaUj0XyK8d1vX-3TUjOjiLxOLJ6cAJ-au2g_v0dzmZ-diG6IC00g9yqSOnAeO7hxPGvdhN1DTBQjNd3ufV40pqjtmStZto8PZOXg8xRsiO145t6xxnQ",
    "refresh_token": "M0x4U-9fHsJVOHrtR3ChqItlYm1Rs3xyckY_2MjfbwQaMz6YsKx1O8njJSDxH4YdHdbilny13IwR4ZnNh4jSmQjH88nmap0LstR84WgT7wwRrBQa2Nfm1FqVfuv2NdCt",
    "scope": "openid profile",
    "id_token": "eyJraWQiOiJjMmRlMTFlMy0zNmViLTQ3NzUtYWRhZi1mMzczNjE1ZDIwZTQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoib2lkYy1jbGllbnQiLCJhenAiOiJvaWRjLWNsaWVudCIsImF1dGhfdGltZSI6MTcyNDMzOTMxMSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNzI0MzQxMzg1LCJpYXQiOjE3MjQzMzk1ODUsImp0aSI6ImI1OTAxOTM1LTRkZmQtNGU5Yy1hYjg3LTUyYjBkMmE1NTZmMyIsInNpZCI6InRzSldBdFRGSmlHMTdoNmhKbmhObGJJaGs4N28taFlmaUZTTFRTUEM3TEEifQ.EZJ__T8gXBXEHLOVNqMT1ePrMqXt25Hx95G_8xKkJHjHyLELI6uxmGiUwWu4aAcqlLiKLu-Jrv7cdNpPCgsXotzCGzKTXylKuAs3BGtKG-nSn4IDCjEV_8OvkI5KFrQw-j75t5mFrDl5nJ8UWjMoS228zIFhS_Xc8dZLyaBwNFpFTfWE8gcSuAKUVELsXw1O_MU95JvbnZiB-DBjSHDum3iciwlRuwkDEqE9CvHihmFR-0YY_PCS0Ia4XEgy1tbTev5XKzGpslBF8IEgNWL6nlGVEiONCv30Iz01ekMohvGBN9E0n6LoB4TC9rYnb5XicnN7ypBDeopKPr_5Bf87qg",
    "token_type": "Bearer",
    "expires_in": 300
}
```