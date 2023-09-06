using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Models {
    public class JWTDbContext : IdentityDbContext<ApplicationUser> {
        public JWTDbContext(DbContextOptions<JWTDbContext> options) : base(options){}
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
        }

    }
}
