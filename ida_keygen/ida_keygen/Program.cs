using ida_keygen;
using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

class Program
{
    const string AppDescription = "IDA Pro Keygen by TOM_RUS";

    static void Main(string[] args)
    {
        CommandLineApplication cmdApp = new CommandLineApplication();
        cmdApp.Name = "ida_keygen";
        cmdApp.FullName = AppDescription;
        var idaVersionOption = cmdApp.Option<int>("-v", "IDA Version", CommandOptionType.SingleValue, (c) => { c.DefaultValue = 770; });
        var idaUserOption = cmdApp.Option<string>("-u", "User name [Required]", CommandOptionType.SingleValue, (c) => { c.IsRequired(); });
        var idaEmailOption = cmdApp.Option<string>("-e", "Email address [Required]", CommandOptionType.SingleValue, (c) => { c.IsRequired(); });
        var idaNumSeatsOption = cmdApp.Option<int>("-n", "Number of seats", CommandOptionType.SingleValue, (c) => { c.DefaultValue = 99; });
        var idaLicenseTypeOption = cmdApp.Option<LicenseType>("-t", "License type [Required]", CommandOptionType.SingleValue, (c) => { c.IsRequired(); });
        var idaLicenseIssueOption = cmdApp.Option<DateTimeOffset>("-i", "License issue date", CommandOptionType.SingleValue, (c) => { c.DefaultValue = DateTimeOffset.Now; });
        var idaSupportDaysOption = cmdApp.Option<int>("-s", "Support expire period (days)", CommandOptionType.SingleValue, (c) => { c.DefaultValue = 15 * 365; });
        var idaLicenseDaysOption = cmdApp.Option<int>("-l", "License expire period (days). Use 0 for Never", CommandOptionType.SingleValue, (c) => { c.DefaultValue = 0; });
        cmdApp.HelpOption("-h");

        void DefaultErrorHandler(ValidationResult validationResult)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine(validationResult.ErrorMessage);
            Console.ResetColor();
            cmdApp.ShowHelp();
        }

        cmdApp.ValidationErrorHandler = (x) =>
        {
            DefaultErrorHandler(x);
            return 0;
        };

        cmdApp.OnExecute(() =>
        {
            IdaLicense idl = new IdaLicense();

            (License newLic, IEnumerable<string> licenseText) = idl.GenerateNewLicense(
                idaVersionOption.ParsedValue,
                idaUserOption.ParsedValue,
                idaEmailOption.ParsedValue,
                idaNumSeatsOption.ParsedValue,
                idaLicenseTypeOption.ParsedValue,
                idaLicenseIssueOption.ParsedValue,
                idaSupportDaysOption.ParsedValue,
                idaLicenseDaysOption.ParsedValue);

            foreach (var line in licenseText)
            {
                Console.WriteLine(line);
            }

            //idl.DisplayLicense(newLic);
        });

        try
        {
            cmdApp.Execute(args);
        }
        catch (CommandParsingException e)
        {
            DefaultErrorHandler(new ValidationResult(e.Message));
        }
    }
}
