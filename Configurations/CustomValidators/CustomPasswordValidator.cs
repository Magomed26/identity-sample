using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace IdentitySample.Configurations.CustomValidators
{
    public class CustomPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> userManager, TUser user, string password)
        {
            var username = await userManager.GetUserNameAsync(user);
            if (username.ToLower().Equals(password.ToLower()))
            {
                return IdentityResult.Failed(new IdentityError
                    {Description = "Username and password can't be the same", Code = "SomeUserPass"});
            }

            if (password.ToLower().Contains("password"))
            {
                return IdentityResult.Failed(new IdentityError
                    {Description = "The word 'password' is not allowed for the password", Code = "PasswordContainsPassword"});
            }
            
            return IdentityResult.Success;
        }
    }
}