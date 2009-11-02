namespace TimeSync
{
    using System;

    public class Synchronizer
    {
		private static readonly string TimeServer;

        static Synchronizer()
        {
			// Modify the server name as desired
			TimeServer = "tick.usno.navy.mil";
        }

        public static int Main(string[] args)
        {
			Console.WriteLine("Time Synchronizer (C)2001 Valer BOCAN <vbocan@dataman.ro>");
			Console.WriteLine("This program implements the Simple Network Time Protocol (see RFC 2030)\r\n");
			Console.WriteLine("Connecting to: {0}\r\n", TimeServer);

			NTPClient client;
			try {
				client = new NTPClient(TimeServer);
				client.Connect(true);
			}
			catch(Exception e)
			{
				Console.WriteLine("ERROR: {0}", e.Message);
				return -1;
			}
			
			Console.Write(client.ToString());
            return 0;
        }
    }
}
