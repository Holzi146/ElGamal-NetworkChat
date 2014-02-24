using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Numerics;
using System.Xml.Serialization;
using System.IO;

namespace Server
{
    class Program
    {
        static Socket s, c;
        static IPEndPoint endp, ipendp;
        static Random zufall = new Random();
        static KeyStruct publicKey, privateKey;
        static byte[] buffer = new byte[1024];
        
        static void Main(string[] args)
        {
            Console.Title = "ElGamal Chat";
            Console.WriteLine("Welcome to the ElGamal Chat System!\n");

            KeyScheduling(ref publicKey, ref privateKey);

            Console.WriteLine("Waiting for connections...\n");

            s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            endp = new IPEndPoint(IPAddress.Any, 1234);
            s.Bind(endp);         
            s.Listen(3);
            s.BeginAccept(new AsyncCallback(DoAccept), s);

            Console.ReadLine();
        }

        private static void KeyScheduling(ref KeyStruct publicKey, ref KeyStruct privateKey)
        {
            byte[] buffer = new byte[sizeof(UInt64)];
            /* q brauchen wir für das Erzeugen einer Sophie-Germain-Primzahl */
            ulong q;

            /* zuerst wird das q bestimmt, um so ein passendes p zu finden, *
             * dies bringt den Vorteil, dass durch Sophie-Germain Zahlen die Primfaktorzerlegung für das g wegfällt */
            do
            {
                zufall.NextBytes(buffer);
                q = BitConverter.ToUInt64(buffer, 0);
                /* durch das Shiften um eine Stelle wird erreicht, dass p durch die Multiplikation mit 2 und q nicht seinen Wertebereich überschreitet */
                q >>= 1;
            }
            while (!MillerRabin(q) || !SophieGermain(q));

            ulong p = (q << 1) + 1;
            Console.WriteLine("p = " + p);

            /* Bestimmung des Generatorpolynoms --> ist jetzt relativ einfach, da die beiden primen Teiler von phi(p) 2 und q sind */
            ulong g = GetGenerator(p, q);
            Console.WriteLine("g = " + g);

            /* ein zufälliges geheimes a wird gewählt --> wichtig für den Private Key */
            zufall.NextBytes(buffer);
            ulong a = BitConverter.ToUInt64(buffer, 0) % p;
            Console.WriteLine("a = " + a);

            /* das große (öffentliche) A wird errechnet, mit dessen Hilfe Nachrichten verschlüsselt werden können */
            ulong A = (ulong) BigInteger.ModPow(g, a, p);
            Console.WriteLine("A = " + A + "\n");

            publicKey = new KeyStruct { p = p, g = g, A = A };
            privateKey = new KeyStruct { a = a };
        }

        private static bool SophieGermain(ulong zahl)
        {
            if (MillerRabin((zahl << 1) + 1))
                return true;
            return false;
        }

        private static ulong GetGenerator(ulong p, ulong q)
        {
            ulong g;         
            byte[] buffer = new byte[sizeof(UInt64)];

            while (true)
            {
                zufall.NextBytes(buffer);
                /* um zu garantieren, dass g in der Menge von p ist, wird % p gerechnet */
                g = BitConverter.ToUInt64(buffer, 0) % p;
                /* dadurch, dass wir Sophie-Germain Zahlen als p verwenden (sprich die primen Teiler von phi(p) 2 und q sind,s
                 * müssen bei der Überprüfung eines Generatorpolynoms nur diese zwei Zahlen herangezogen werden */
                if(BigInteger.ModPow(g,q,p) != 1 && BigInteger.ModPow(g,2,p) != 1)
                    return g;
            }
        }

        /* Primzahltest nach dem MillerRabin-Verfahren */
        private static bool MillerRabin(BigInteger zahl)
        {
            /* wenn die Zahl durch zwei teilbar ist */
            if ((zahl & 1) == 0)
                return false;

            BigInteger d = zahl - 1;
            int s = 0;

            while ((d & 1) == 0)  {  d >>= 1; s++;  }

            /* nach vier Versuchen hat man bereits eine Wahrscheinlichkeit von unter 0,04% */
            for (int a = 2; a < 6; a++)
            {
                BigInteger x = BigInteger.ModPow(a, d, zahl);
                if (x == 1 || x == zahl - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, zahl);
                    if (x == 1)
                        return false;
                    if (x == zahl - 1)
                        break;
                }

                if (x != zahl - 1)
                    return false;
            }
            return true;
        }

        private static void DoAccept(IAsyncResult res)
        {
            s = (Socket)res.AsyncState;
            c = s.EndAccept(res);
            s.BeginAccept(new AsyncCallback(DoAccept), s);
            SocketObject sObject = new SocketObject { clientSocket = c };

            ipendp = (IPEndPoint)c.RemoteEndPoint;
            Console.WriteLine(ipendp.Address + " --CONNECT--");

            /* öffentlicher Schlüssel wird serialisiert und verschickt */
            XmlSerializer xml_ser = new XmlSerializer(typeof(KeyStruct));
            MemoryStream str = new MemoryStream();
            xml_ser.Serialize(str, publicKey);
            buffer = str.ToArray();
            c.BeginSend(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(DoSend), c);
            str.Close();

            /* Nachrichten werden empfangen */
            sObject.buffer = new byte[4096];
            c.BeginReceive(sObject.buffer, 0, 4096, SocketFlags.None, new AsyncCallback(DoReceive), sObject);
        }

        private static void DoReceive(IAsyncResult res)
        {
            try
            {
                SocketObject sObject = (SocketObject)res.AsyncState;
                sObject.clientSocket.EndReceive(res);

                XmlSerializer xml_ser = new XmlSerializer(typeof(KeyStruct));
                MemoryStream str = new MemoryStream(sObject.buffer);
                /* Objekt deserialisieren und entschlüsseln */
                Console.WriteLine(ipendp.Address + " " + ElGamalDecrypt((KeyStruct)xml_ser.Deserialize(str), privateKey));
                str.Close();

                /* Wiederholen des Receive-Vorgangs */
                sObject.buffer = new byte[4096];
                sObject.clientSocket.BeginReceive(sObject.buffer, 0, 4096, SocketFlags.None, new AsyncCallback(DoReceive), sObject);
            }
            catch (Exception)
            {
                Console.WriteLine(ipendp.Address + " --DISCONNECT--\n");
            }          
        }

        private static void DoSend(IAsyncResult res)
        {
            c.EndSend(res);
        }

        private static string ElGamalDecrypt(KeyStruct cipher, KeyStruct privateKey)
        {
            string m = "";
            ulong x = publicKey.p - 1 - privateKey.a;

            /* jedes Zeichen wird wieder entschlüsselt */
            for (int i = 0; i < cipher.c.Length; i++)
                m += char.ConvertFromUtf32((int)((BigInteger.ModPow(cipher.B, x, publicKey.p) * cipher.c[i]) % publicKey.p));          
            return m;
        }
    }

    [Serializable]
    public class KeyStruct
    {
        public ulong p { get; set; }
        public ulong g { get; set; }
        public ulong a { get; set; }
        public ulong A { get; set; }
        public ulong B { get; set; }
        public ulong b { get; set; }
        public ulong [] c { get; set; }
    }

    public class SocketObject
    {
        public byte[] buffer = new byte[4096];
        public Socket clientSocket;
    }
}
