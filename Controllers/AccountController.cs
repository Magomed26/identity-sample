using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AutoMapper;
using IdentitySample.Models;
using IdentitySample.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentitySample.Controllers
{
    public class AccountController : Controller
    {
        private readonly IMapper _mapper;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<User> userManager, IMapper mapper, SignInManager<User> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _mapper = mapper;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(UserRegistrationModel registrationModel)
        {
            if (!ModelState.IsValid)
                return View(registrationModel);

            var user = _mapper.Map<User>(registrationModel);

            var result = await _userManager.CreateAsync(user, registrationModel.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }

                return View(registrationModel);
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new {token, email = user.Email}, Request.Scheme);
            var message = $"To confirm email click <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>here</a>";
            await _emailSender.SendEmailAsync(user.Email, "Email confirmation", message);

            await _userManager.AddToRoleAsync(user, "Visitor");

            return RedirectToAction(nameof(SuccessRegistration));
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return View(nameof(Error));
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            return View(result.Succeeded ? nameof(ConfirmEmail) : nameof(Error));
        }

        [HttpGet]
        public IActionResult SuccessRegistration()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Error()
        {
            return View();
        }
        
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UserLoginModel loginModel, string returnUrl)
        {
            if (!ModelState.IsValid)
                return View(loginModel);

            var result = await _signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password,
                loginModel.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded) 
                return RedirectToLocal(returnUrl);

            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginTwoStep), new {loginModel.Email, loginModel.RememberMe, returnUrl});
            }
            
            if (result.IsLockedOut)
            {
                var forgotPasswordLink = Url.Action(nameof(ForgotPassword), "Account", new { }, Request.Scheme);
                var message =
                    $"Your account is locked out, to reset your password, please click this link: {forgotPasswordLink}";
                await _emailSender.SendEmailAsync(loginModel.Email, "Locked out account information", message);
                ModelState.AddModelError("", "The account is locked out");
                return View();
            }

            ModelState.AddModelError("", "Invalid login attempt");
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> LoginTwoStep(string email, bool rememberMe, string returnUrl = null)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return View(nameof(Error));
            }

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains("Email"))
            {
                return View(nameof(Error));
            }

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            await _emailSender.SendEmailAsync(email, "Authentication token", token);
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost] 
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginTwoStep(TwoStepModel twoStepModel, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(twoStepModel);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user is null)
            {
                return RedirectToAction(nameof(Error));
            }

            var result =
                await _signInManager.TwoFactorSignInAsync("Email", twoStepModel.TwoFactorCode, twoStepModel.RememberMe,
                    rememberClient: false);

            if (result.Succeeded)
            {
                return RedirectToLocal(returnUrl);
            }

            if (result.IsLockedOut)
            {
                var forgotPasswordLink = Url.Action(nameof(ForgotPassword), "Account", new { }, Request.Scheme);
                var message =
                    $"Your account is locked out, to reset your password, please click this link: {forgotPasswordLink}";
                await _emailSender.SendEmailAsync(user.Email, "Locked out account information", message);
                ModelState.AddModelError("", "The account is locked out");
                return View();
            }

            ModelState.AddModelError("", "Invalid login attempt");
            return View();
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (!Url.IsLocalUrl(returnUrl))
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return Redirect(returnUrl);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new {returnUrl});
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null)
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info is null)
            {
                return RedirectToAction(nameof(Login), "Account");
            }

            var sigInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,
                isPersistent: false, bypassTwoFactor: true);

            if (sigInResult.Succeeded)
            {
                return RedirectToLocal(returnUrl);
            }

            if (sigInResult.IsLockedOut)
            {
                return RedirectToAction(nameof(ForgotPassword), "Account");
            }

            ViewData["returnUrl"] = returnUrl;
            ViewData["Provider"] = info.LoginProvider;
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            return View("ExternalLogin", new ExternalLoginModel {Email = email});
        }

        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(model);
            
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return View(nameof(Error));
            var user = await _userManager.FindByEmailAsync(model.Email);
            IdentityResult result;
            if(user != null)
            {
                result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToLocal(returnUrl);
                }
            }
            else
            {
                model.ClaimsPrincipal = info.Principal;
                user = _mapper.Map<User>(model);
                result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        //TODO: Send an emal for the email confirmation and add a default role as in the Register action
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
            }
            
            foreach (var error in result.Errors)
            {
                ModelState.TryAddModelError(error.Code, error.Description);
            }
            return View(nameof(ExternalLogin), model);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {
            if (!ModelState.IsValid)
            {
                return View(forgotPasswordModel);
            }

            var user = await _userManager.FindByEmailAsync(forgotPasswordModel.Email);
            if (user is null)
            {
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new {token, email = user.Email}, Request.Scheme);
            var message = $"To reset password click <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>here</a>";
            
            await _emailSender.SendEmailAsync(user.Email, "Reset password", message);
            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }
        
        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordModel {Token = token, Email = email};
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            if (!ModelState.IsValid)
            {
                return View(resetPasswordModel);
            }

            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);

            if (user is null)
            {
                RedirectToAction(nameof(ResetPasswordConfirmation));
            }

            var resetPasswordResult =
                await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.Password);

            if (!resetPasswordResult.Succeeded)
            {
                foreach (var error in resetPasswordResult.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }

                return View();
            }

            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }
    }
}