using System.ComponentModel.DataAnnotations;

namespace IdentitySample.Models
{
    public class TwoStepModel
    {
        [Required]
        [DataType(DataType.Text)]
        public string TwoFactorCode { get; set; }

        public bool RememberMe { get; set; }
    }
}