using System.ComponentModel.DataAnnotations;

namespace IdentitySample.Models
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}