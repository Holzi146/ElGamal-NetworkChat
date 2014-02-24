using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Net;
using System.Net.Sockets;
using System.Xml.Serialization;
using System.IO;
using System.Numerics;

namespace Client
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        Socket s;
        Random zufall = new Random();
        KeyStruct publicKey, cipher;
        byte[] buffer = new byte[1024];

        private void btn_connect_Click(object sender, RoutedEventArgs e)
        {
            s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                s.BeginConnect(new IPEndPoint(IPAddress.Parse(tbx_ip.Text), 1234), new AsyncCallback(DoConnect), s);
                btn_connect.IsEnabled = false;
            }
            catch (Exception)
            {
                MessageBox.Show("Ungültige IP-Adresse!");
            }
            tbx_ip.Text = "";          
        }

        private void DoConnect(IAsyncResult res)
        {
            try
            {
                s = (Socket)res.AsyncState;
                s.EndConnect(res);
                s.BeginReceive(buffer, 0, 1024, SocketFlags.None, new AsyncCallback(DoReceive), s);
            }
            catch (Exception)
            {
                MessageBox.Show("Verbindung fehlgeschlagen!");
            }           
        }

        private void DoReceive(IAsyncResult res)
        {
            Socket c = (Socket)res.AsyncState;
            c.EndReceive(res);
            XmlSerializer xml_ser = new XmlSerializer(typeof(KeyStruct));
            MemoryStream str = new MemoryStream(buffer);
            /* Objekt deserialisieren und daraus den publicKey holen */
            publicKey = (KeyStruct)xml_ser.Deserialize(str);
            str.Close();

            /* Erzeugung des großen B's --> g mit einem zufälligem Exponenten (kleines b) hochrechnen */
            buffer = new byte[sizeof(UInt64)];
            zufall.NextBytes(buffer);            
            publicKey.b = BitConverter.ToUInt64(buffer, 0) % publicKey.p;
            cipher = new KeyStruct {  B = (ulong)BigInteger.ModPow(publicKey.g, publicKey.b, publicKey.p)  };

            Dispatcher.Invoke((Action)delegate 
            {
                img_check.Visibility = Visibility.Visible;
                lbl_keyReceived.Visibility = Visibility.Visible;
                btn_send.IsEnabled = true;
            });           
        }

        private void btn_send_Click(object sender, RoutedEventArgs e)
        {
            XmlSerializer xml_ser = new XmlSerializer(typeof(KeyStruct));
            MemoryStream str = new MemoryStream();
            if (tbx_input.Text.Length > 71)
            {
                MessageBox.Show("Es sind nur maximal 71 Zeichen erlaubt!");
                tbx_input.Text = "";
                tbx_input.Focus();
                return;
            }
            /* Ciphertext aus der Textbox und dem publicKey generieren */
            cipher.c = ElGamalEncrypt(tbx_input.Text, publicKey);
            /* Objekt serialisieren */
            xml_ser.Serialize(str, cipher);
            buffer = str.ToArray();
            str.Close();

            try
            {
                s.BeginSend(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(DoSend), s);
            }
            catch (Exception)
            {
                MessageBox.Show("Server ist down!");
            }        
   
            tbx_input.Text = "";
            tbx_input.Focus();
        }

        private void DoSend(IAsyncResult res)
        {
            s.EndSend(res);
        }

        private ulong[] ElGamalEncrypt(string input, KeyStruct publicKey)
        {
            ulong[] c = new ulong[input.Length];

            /* jedes Zeichen wird extra verschlüsselt und dann Element eines ulong[]'s */
            for (int i = 0; i < input.Length; i++)
                c[i] = (ulong)((BigInteger.ModPow(publicKey.A, publicKey.b, publicKey.p) * (int)input.ElementAt(i)) % publicKey.p);
            return c;
        }

        private void tbx_input_TextChanged(object sender, TextChangedEventArgs e)
        {
            int count = 71 - tbx_input.Text.Length;
            if (count < 0) count = 0;
            lbl_zeichen.Content = "Geben Sie einen Text ein : (noch " + count.ToString() + " Zeichen übrig)";
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
        public ulong[] c { get; set; }
    }
}
