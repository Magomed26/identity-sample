using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;


namespace IdentitySample.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var smtpSection = _configuration.GetSection("smtp");
            var smtpEmail = smtpSection["email"];

            var from = new MailAddress(smtpEmail, "Site administration", System.Text.Encoding.UTF8);

            var to = new MailAddress(email);

            using var mailMessage = new MailMessage(from, to)
            {
                Subject = subject,
                Body = htmlMessage,
                IsBodyHtml = true
            };

            using var client = new SmtpClient(smtpSection["server"])
            {
                Port = Convert.ToInt32(smtpSection["port"]),
                EnableSsl = Convert.ToBoolean(smtpSection["enableSSL"]),
                Credentials = new NetworkCredential(smtpEmail, smtpSection["password"])
            };

            await client.SendMailAsync(mailMessage);
        }
    }
}