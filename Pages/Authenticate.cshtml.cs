using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace OAuth.AuthorizationServer.Pages
{
    public class AuthenticateModel : PageModel
    {
        public string Email { get; set; } = Consts.Email;
        public string password { get; set; } = Consts.password;

        [BindProperty]
        public string ReturnUrl { get; set; }
        public string AuthStatus { get; set; } = "";

        public IActionResult OnGet(string returnurl)
        {
            ReturnUrl = returnurl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string email,string password)
        {
            if (email != Consts.Email || password != Consts.password)
            {
                AuthStatus = "cannot authenticate";
                return Page();
            }
            var claim = new List<Claim>
            {
                new Claim(ClaimTypes.Email,email)
            };
            var principal = new ClaimsPrincipal(
                new List<ClaimsIdentity>
                {
                    new ClaimsIdentity(claim,CookieAuthenticationDefaults.AuthenticationScheme)
                }) ;

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            if (!string.IsNullOrEmpty(ReturnUrl))
            {
                try
                {
                    return Redirect(ReturnUrl);
                }
                catch (Exception ex)
                {

                    throw new InvalidOperationException(ex.Message);
                }

            }
            AuthStatus = "Authenticated";
            return Page();
        }
    }
}
