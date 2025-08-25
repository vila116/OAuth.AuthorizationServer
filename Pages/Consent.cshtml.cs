using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace OAuth.AuthorizationServer.Pages
{
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class ConsentModel : PageModel
    {
        [BindProperty]
        public string ReturnUrl { get; set; }
        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }
        public async Task<IActionResult> OnPostAsync(string grant)
        {
            if (grant != Consts.GrantAccessValue)
            {
                return Forbid();
            }

            var ConsentClaim = User.GetClaim(Consts.ConsentNaming);
            if (string.IsNullOrEmpty(ConsentClaim))
            {
                User.SetClaim(Consts.ConsentNaming, grant);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,User);
            }
            return Redirect(ReturnUrl);
        }
    }
}
