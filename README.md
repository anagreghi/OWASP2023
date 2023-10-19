# OWASP2023 - OWASP Top 10 - Segurança em Aplicações Web

Este repositório contém exemplos e práticas recomendadas para abordar as principais vulnerabilidades de segurança em aplicações web, conforme descrito pelo OWASP Top 10. Cada seção a seguir aborda um tópico específico do OWASP Top 10, fornecendo um exemplo de código vulnerável, uma solução segura e uma breve explicação.

## Índice

1. [A1: Broken Access Control](#a1-broken-access-control)
2. [A2: Cryptographic Failures](#a2-cryptographic-failures)
3. [A3: Injection](#a3-injection)
4. [A4: Insecure Design](#a4-insecure-design)
5. [A5: Security Misconfiguration](#a5-security-misconfiguration)
6. [A6: Vulnerable and Outdated Components](#a6-vulnerable-and-outdated-components)
7. [A7: Identification and Authentication Failures](#a7-identification-and-authentication-failures)
8. [A8: Software and Data Integrity Failures](#a8-software-and-data-integrity-failures)
9. [A9: Security Logging and Monitoring Failures](#a9-security-logging-and-monitoring-failures)
10. [A10: Server-Side Request Forgery (SSRF)](#a10-server-side-request-forgery-ssrf)

## A1: Broken Access Control

### Exemplo de Código Vulnerável

```csharp
public class UserController : Controller
{
    public ActionResult EditProfile(int userId)
    {
        User user = userService.GetUserById(userId);
        return View(user);
    }
}
```

### Solução
```csharp
public class UserController : Controller
{
    private readonly IUserService userService;
    private readonly IAuthenticationService authenticationService;

    public UserController(IUserService userService, IAuthenticationService authenticationService)
    {
        this.userService = userService;
        this.authenticationService = authenticationService;
    }

    public ActionResult EditProfile(int userId)
    {
        var currentUser = authenticationService.GetCurrentUser();
        if (currentUser.Id != userId && !currentUser.IsAdmin)
        {
            return new HttpUnauthorizedResult();
        }

        User user = userService.GetUserById(userId);
        return View(user);
    }
}
```

### Explicação
Verifique se o usuário autenticado tem permissão para acessar o recurso solicitado. Limite o acesso com base em funções ou permissões.

## A2: Cryptographic Failures
### Exemplo de Código Vulnerável

```csharp
public class PasswordService
{
    public bool ValidatePassword(string enteredPassword, string storedHash)
    {
        return BCrypt.Net.BCrypt.Verify(enteredPassword, storedHash);
    }
}
```

### Solução
```csharp
public class PasswordService
{
    public bool ValidatePassword(string enteredPassword, string storedHash)
    {
        return BCrypt.Net.BCrypt.Verify(enteredPassword, storedHash);
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
}
```

### Explicação
Use algoritmos de hashing de senhas seguros, como bcrypt, para armazenar e verificar senhas.

## A3: Injection
### Exemplo de Código Vulnerável

```csharp
public class UserService
{
    public User GetUserByEmail(string email)
    {
        string query = $"SELECT * FROM Users WHERE Email = '{email}'";
        return database.ExecuteQuery(query);
    }
}
```

### Solução
```csharp
public class UserService
{
    public User GetUserByEmail(string email)
    {
        string query = "SELECT * FROM Users WHERE Email = @Email";
        var parameters = new { Email = email };
        return database.ExecuteQuery(query, parameters);
    }
}
```

### Explicação
Utilize parâmetros em consultas SQL para evitar injeção de SQL.

## A4: Insecure Design
### Exemplo de Código Vulnerável

```csharp
public class FileUploadController : Controller
{
    public ActionResult Upload(HttpPostedFileBase file)
    {
        string path = Path.Combine(Server.MapPath("~/Uploads"), file.FileName);
        file.SaveAs(path);
        return View();
    }
}
```

### Solução
```csharp
public class FileUploadController : Controller
{
    private readonly List<string> allowedExtensions = new List<string> { ".jpg", ".png", ".pdf" };

    public ActionResult Upload(HttpPostedFileBase file)
    {
        string extension = Path.GetExtension(file.FileName).ToLower();
        if (!allowedExtensions.Contains(extension))
        {
            return new HttpStatusCodeResult(HttpStatusCode.BadRequest, "Tipo de arquivo não permitido.");
        }

        string path = Path.Combine(Server.MapPath("~/Uploads"), Path.GetFileName(file.FileName));
        file.SaveAs(path);
        return View();
    }
}
```

### Explicação
Implemente verificações de tipo de arquivo e outros controles de segurança no upload de arquivos.

## A5: Security Misconfiguration
### Exemplo de Código Vulnerável

```csharp
public class ConfigurationManager
{
    public string GetConnectionString()
    {
        return ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;
    }
}
```

### Solução
```csharp
public class ConfigurationManager
{
    public string GetConnectionString()
    {
        var connectionString = ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString;
        return connectionString;
    }
}
```

### Explicação
Proteja informações sensíveis e use mecanismos seguros para gerenciar configurações e segredos.

## A6: Vulnerable and Outdated Components
### Exemplo de Código Vulnerável

```csharp
public class ComponentChecker
{
    public void CheckComponents()
    {
        var componentVersion = "1.0.0";
        if (componentVersion == "1.0.0")
        {
            // Componente vulnerável
        }
    }
}
```

### Solução
```csharp
public class ComponentChecker
{
    public void CheckComponents()
    {
        var currentVersion = GetCurrentComponentVersion();
        var latestVersion = GetLatestComponentVersionFromDatabase();

        if (currentVersion < latestVersion)
        {
            // Atualizar o componente
        }
    }

    private string GetCurrentComponentVersion()
    {
        return "1.0.0";
    }

    private string GetLatestComponentVersionFromDatabase()
    {
        return "1.1.0";
    }
}
```

### Explicação
Verifique e mantenha seus componentes atualizados e seguros.

## A7: Identification and Authentication Failures
### Exemplo de Código Vulnerável

```csharp
public class AuthService
{
    public bool ValidateUser(string username, string password)
    {
        User user = userRepository.GetUserByUsername(username);
        return user != null && user.Password == password; // Sem hashing
    }
}
```

### Solução
```csharp
public class AuthService
{
    private readonly IUserRepository userRepository;

    public AuthService(IUserRepository userRepository)
    {
        this.userRepository = userRepository;
    }

    public bool ValidateUser(string username, string password)
    {
        User user = userRepository.GetUserByUsername(username);
        if (user == null)
        {
            return false;
        }

        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }

    public void RegisterUser(string username, string password)
    {
        string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);
        userRepository.AddUser(username, hashedPassword);
    }
}
```

### Explicação
Use hashing para senhas e implemente práticas de autenticação seguras.

## A8: Software and Data Integrity Failures
### Exemplo de Código Vulnerável

```csharp
public class FileService
{
    public void SaveFile(string path, byte[] content)
    {
        File.WriteAllBytes(path, content);
    }
}
```

### Solução
```csharp
public class FileService
{
    public void SaveFile(string path, byte[] content, string expectedChecksum)
    {
        string actualChecksum = ComputeChecksum(content);

        if (actualChecksum != expectedChecksum)
        {
            throw new InvalidOperationException("Checksum inválido. O arquivo pode ter sido comprometido.");
        }

        File.WriteAllBytes(path, content);
    }

    private string ComputeChecksum(byte[] content)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] hashBytes = sha256.ComputeHash(content);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }
}
```

### Explicação
Verifique a integridade dos dados usando checksums ou assinaturas digitais.

## A9: Security Logging and Monitoring Failures
### Exemplo de Código Vulnerável

```csharp
public class OrderService
{
    public void PlaceOrder(Order order)
    {
        ProcessOrder(order);
    }
}
```

### Solução
```csharp
public class OrderService
{
    private readonly ILogger<OrderService> logger;

    public OrderService(ILogger<OrderService> logger)
    {
        this.logger = logger;
    }

    public void PlaceOrder(Order order)
    {
        logger.LogInformation($"Order placed: {order.Id}");
        ProcessOrder(order);
    }
}
```

### Explicação
Implemente o registro de eventos e monitore atividades para detectar e responder a possíveis incidentes de segurança.

## A10: Server-Side Request Forgery (SSRF)
### Exemplo de Código Vulnerável

```csharp
public class RemoteFileFetcher
{
    public string FetchData(string url)
    {
        using (var client = new WebClient())
        {
            return client.DownloadString(url);
        }
    }
}
```

### Solução
```csharp
public class RemoteFileFetcher
{
    private static readonly HashSet<string> allowedHosts = new HashSet<string>
    {
        "api.example.com",
        "services.example.com"
    };

    public string FetchData(string url)
    {
        var uri = new Uri(url);
        if (!allowedHosts.Contains(uri.Host))
        {
            throw new InvalidOperationException("Host não permitido.");
        }

        using (var client = new WebClient())
        {
            return client.DownloadString(url);
        }
    }
}
```

### Explicação
Restrinja os destinos para solicitações externas para evitar o acesso a recursos internos ou maliciosos.
