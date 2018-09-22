using System;
using System.IO;

public class Program
{
	static int Main(string[] args)
	{
		Console.WriteLine("SoftEther VPN Project");
		Console.WriteLine("STB File Multilanguage Full-Mesh Consistency Checker");
		Console.WriteLine("");

		if (args.Length != 1)
		{
			Console.WriteLine("Usage: dotnet run [hamcore_dir]");
			return -1;
		}
		else
		{
			string hamcore_dir = args[0];

			string[] stb_files = Directory.GetFiles(hamcore_dir, "*.stb", SearchOption.TopDirectoryOnly);

			if (stb_files.Length == 0)
			{
				Console.WriteLine("Error: There are no .stb files in the directory '" + hamcore_dir + "'.");
				return -1;
			}

			int total_num = 0;

			for (int i = 0; i < stb_files.Length; i++)
			{
				for (int j = 0; j < stb_files.Length; j++)
				{
					if (i != j)
					{
						Console.WriteLine("---\nComparing '{1}' to '{0}'...", Path.GetFileName(stb_files[i]), Path.GetFileName(stb_files[j]));

						total_num += Stb.Compare(stb_files[i], stb_files[j]);
					}
				}
			}

			Console.WriteLine("--- Results ---");
			if (total_num == 0)
			{
				Console.WriteLine("OK: Excellent! There are no errors between multilanguage stb files.");
				Console.WriteLine();
				Console.WriteLine("   - In Jurassic Park: \"It's a UNIX system! I know this!\"");
				return 0;
			}
			else
			{
				Console.WriteLine($"ERROR: There are {total_num} errors on multilanguage stb files. Please kindly correct them before submitting us Pull Requests.");
				return -3;
			}
		}
	}
}
