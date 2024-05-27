using JwtAuthAspNetWebAPI.Core.Dtos;
using JwtAuthAspNetWebAPI.Core.Entities;
using JwtAuthAspNetWebAPI.Core.Interfaces;
using JwtAuthAspNetWebAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthAspNetWebAPI.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user is null)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Crendentials"
                };

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPasswordCorrect)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Crendentials"
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);
            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = token
            };
        }
        private string GenerateNewJsonWebToken(List<Claim> Claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: Claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)

                );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;

        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
            if (user is null)
                return new AuthServiceResponseDto() 
                { 
                    IsSucceed = false, 
                    Message = "Invalid Crendentials" 
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return new AuthServiceResponseDto() 
            { 
                IsSucceed = true, 
                Message = "Invalid Crendentials" 
            };
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
            if (user is null)
                return new AuthServiceResponseDto() 
                { 
                    IsSucceed = false, 
                    Message = "Invalid Crendentials" 
                };

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            return new AuthServiceResponseDto() 
            { 
                IsSucceed = true, 
                Message = "Invalid Crendentials" 
            };
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.UserName);
            if (isExistsUser != null)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "UserName Already Exists"
                };

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Because: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return new AuthServiceResponseDto()
                {
                    IsSucceed = true, 
                    Message = errorString 
                };
            }
            //Add a Default USER Role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto() { 
                IsSucceed = true, 
                Message = "Roles Seeding is Already Done" 
            };
        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = true,
                    Message = "Roles Seeding is Already Done"
                };
            }


            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "Roles Seeding Done Succesfully"
            };
        }
    }
}
