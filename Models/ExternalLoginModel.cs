using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace IdentitySample.Models
{
    public class ExternalLoginModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public ClaimsPrincipal ClaimsPrincipal { get; set; }
    }
}