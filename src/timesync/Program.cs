using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace timesync
{
    class Program
    {
        static void Main(string[] args)
        {
            SNTPClient internetTime = new SNTPClient("north-america.pool.ntp.org");
            try
            {
               internetTime.Connect(true);
            }
            catch( Exception e )
            {
               System.Diagnostics.Debug.WriteLine(e.StackTrace);
            }
        }
    }
}
