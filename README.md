# identity-sample
This project demonstrate implementation of functionalities like registration, login using Identity library in ASP.NET Core MVC web application.
Also in this this project you can find lockout, reset password, two-step verification, email confirmation and external login features

This application uses `user-secrets` for configurations.
First you have to init secrets. To do that run 
```bash
dotnet user-secrets init
```

To configure smtp server for the project add following secrets running
```bash
dotnet user-secrets set "smtp:server" "<smtp server>"
dotnet user-secrets set "smtp:port" "<PORT>"
dotnet user-secrets set "smtp:enableSSL" "true/false"
dotnet user-secrest set "smtp:email" "<YOUR_EMAIL>"
dotnet user-secrets set "smtp:password" "<YOUR_PASSWORD>"
``` 
