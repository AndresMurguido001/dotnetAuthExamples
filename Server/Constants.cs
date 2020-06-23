using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public static class Constants
    {
        // These should be stored with app secrets / app settings
        public const string Audience = "https://localhost:44372/";

        public const string Issuer = Audience; // Issuer is set to Audience because the server is issuing tokens to itself
        public const string Secret = "some_seceret_random_assortment_of_letters_and_maybe_numbers_idk"; // Issuer is set to Audience because the server is issuing tokens to itself
    }
}
