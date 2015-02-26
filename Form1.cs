using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace Operacijski_Sustavi
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        public int MachineKeyStore { get; set; }

        public string IzracunajSazetak(string file)
        {
            SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
            FileStream fstreamU = File.OpenRead(file);
            int size = (int)fstreamU.Length;
            byte[] sadrzaj = new byte[size];
            fstreamU.Read(sadrzaj, 0, size);

            fstreamU.Flush();
            fstreamU.Close();
            fstreamU.Dispose();

            byte[] tmpHash;
            tmpHash = sha1.ComputeHash(sadrzaj);
            StringBuilder sOuput = new StringBuilder(tmpHash.Length);

            for (int i = 0; i < tmpHash.Length; i++)
            {
                sOuput.Append(tmpHash[i].ToString("x2"));
            }
            return sOuput.ToString();
        }

        public void GenerirajAKljuceve()
        {
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();

            string javniKljuc = rsaCryptoServiceProvider.ToXmlString(false);
            string privatniKljuc = rsaCryptoServiceProvider.ToXmlString(true);
            TextWriter streamWriter = new StreamWriter("javni_kljuc.txt");
            TextWriter streamWriterSecond = new StreamWriter("privatni_kljuc.txt");
            streamWriter.WriteLine(javniKljuc);
            streamWriterSecond.WriteLine(privatniKljuc);
            streamWriterSecond.Close();
            streamWriter.Close();

            streamWriter.Dispose();
            streamWriterSecond.Dispose();
        }

        public void GenerirajSKljuc()
        {
            Rijndael rijndael = Rijndael.Create();
            string keyb64 = Convert.ToBase64String(rijndael.Key);
            TextWriter streamWriter = new StreamWriter("tajni_kljuc.txt");
            streamWriter.WriteLine(keyb64);
            streamWriter.Close();
            streamWriter.Dispose();
        }

        public void DigitalniPotpis(string file)
        {
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            StreamReader streamReader = new StreamReader("privatni_kljuc.txt");
            string publicOnlyKeyXml = streamReader.ReadToEnd();
            rsaCryptoServiceProvider.FromXmlString(publicOnlyKeyXml);

            streamReader.Close();
            streamReader.Dispose();

            FileStream dat = new FileStream(file, FileMode.Open, FileAccess.Read);

            BinaryReader binReader = new BinaryReader(dat);
            byte[] data = binReader.ReadBytes((int)dat.Length);
            byte[] sign = rsaCryptoServiceProvider.SignData(data, "SHA1");

            binReader.Close();
            binReader.Dispose();
            dat.Close();
            dat.Dispose();

            string datName = file + ".dp";

            TextWriter textWriter = new StreamWriter(datName);
            textWriter.WriteLine(Convert.ToBase64String(sign));
            textWriter.Close();
            textWriter.Dispose();
        }

        public void ProvjeriDigitalniPotpis(string file)
        {
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            StreamReader streamReader = new StreamReader("javni_kljuc.txt");
            string publicKey = streamReader.ReadToEnd();
            rsaCryptoServiceProvider.FromXmlString(publicKey);
            streamReader.Close();
            streamReader.Dispose();

            FileStream dat = new FileStream(file, FileMode.Open, FileAccess.Read);
            BinaryReader binReader = new BinaryReader(dat);
            byte[] data = binReader.ReadBytes((int)dat.Length);
            string nameP = file + ".dp";

            TextReader streamreader = new StreamReader(nameP);
            string sign = streamreader.ReadLine();
            streamreader.Close();
            streamreader.Dispose();

            if (rsaCryptoServiceProvider.VerifyData(data, "SHA1", Convert.FromBase64String(sign)))
            {
                MessageBox.Show("File je digitalno potpisan!");
            }
            else
                MessageBox.Show("File nije digitalno potpisan!");

            binReader.Close();
            binReader.Dispose();
            dat.Close();
            dat.Dispose();
        }

        public void rsaKriptiranje(string file)
        {
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            StreamReader streamReader = new StreamReader("javni_kljuc.txt");
            string javniKljuc = streamReader.ReadToEnd();
            rsaCryptoServiceProvider.FromXmlString(javniKljuc);
            streamReader.Close();

            string record = file + ".rsa";

            FileStream fstreamU = File.OpenRead(file),
            fstreamO = new FileStream(record, FileMode.Create, FileAccess.ReadWrite);

            BinaryWriter bw = new BinaryWriter(fstreamO);

            BinaryReader binReader = new BinaryReader(fstreamU);
            byte[] bytes = binReader.ReadBytes((int)fstreamU.Length);
            binReader.Close();

            byte[] crypt = rsaCryptoServiceProvider.Encrypt(bytes, false);

            bw.Write(crypt);
            bw.Flush();
            bw.Close();
            bw.Dispose();

            fstreamU.Close();
            fstreamU.Dispose();
        }

        public void rsaDekriptiranje(string file)
        {
            MachineKeyStore = 128 * 1024;
            RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();
            RSACryptoServiceProvider.UseMachineKeyStore = false;
            StreamReader streamReader = new StreamReader("privatni_kljuc.txt");
            string privatniKljuc = streamReader.ReadToEnd();
            rsaCryptoServiceProvider.FromXmlString(privatniKljuc);
            streamReader.Close();

            int indexRsa = file.LastIndexOf(".rsa");
            string zapis = file.Substring(0, indexRsa);

            FileStream fstreamU = File.OpenRead(file),
            fstreamO = new FileStream(zapis, FileMode.Create, FileAccess.ReadWrite);

            BinaryWriter binaryWriter = new BinaryWriter(fstreamO);
            BinaryReader binaryReader = new BinaryReader(fstreamU);
            byte[] bytes = binaryReader.ReadBytes((int)fstreamU.Length);

            binaryReader.Close();

            byte[] decrypt = rsaCryptoServiceProvider.Decrypt(bytes, false);
            binaryWriter.Write(decrypt);

            binaryWriter.Flush();
            binaryWriter.Close();
            binaryWriter.Dispose();

            fstreamU.Close();
            fstreamU.Dispose();
        }

        public void aesKriptiranje (string file)
        {
            string zapis;
            zapis = file + ".aes";
            FileStream fstreamU = File.OpenRead(file),
            fstreamO = File.OpenWrite(zapis);
            long lSize = fstreamU.Length;

            MachineKeyStore = 128 * 1024;
            byte[] bytes = new byte[MachineKeyStore];
            int read = -1;

            Rijndael rijndaelAlg = Rijndael.Create();
            rijndaelAlg.Mode = CipherMode.ECB;
            TextReader streamreader = new StreamReader("tajni_kljuc.txt");
            string secretKey = streamreader.ReadLine();
            rijndaelAlg.Key = Convert.FromBase64String(secretKey);
            streamreader.Close();

            CryptoStream cout = new CryptoStream(fstreamO, rijndaelAlg.CreateEncryptor(), CryptoStreamMode.Write);

            BinaryWriter bw = new BinaryWriter(cout);
            bw.Write(lSize);

            while ((read = fstreamU.Read(bytes, 0, bytes.Length)) != 0)
            {
                cout.Write(bytes, 0, read);
            }

            cout.Flush();
            cout.Close();
            cout.Dispose();
            fstreamU.Flush();
            fstreamU.Close();
            fstreamU.Dispose();
        }

        public void aesDekriptiranje(string file, string decryptedFile)
        {
            FileStream fstreamU = File.OpenRead(file), fstreamO = File.OpenWrite(decryptedFile);

			MachineKeyStore = 128 * 1024;
            byte[] bytes = new byte[MachineKeyStore];
            int read = -1;

            SymmetricAlgorithm sma = Rijndael.Create();
            sma.Mode = CipherMode.ECB;

            TextReader tr = new StreamReader("tajni_kljuc.txt");
            string secretKey = tr.ReadLine();
            sma.Key = Convert.FromBase64String(secretKey);
            tr.Close();
			CryptoStream cin = new CryptoStream(fstreamU, sma.CreateDecryptor(), CryptoStreamMode.Read);

            BinaryReader br = new BinaryReader(cin);
            long lSize = br.ReadInt64();

            long numReads = lSize / MachineKeyStore;

            long slack = (long)lSize % MachineKeyStore;

            for (int i = 0; i < numReads; ++i)
            {
                read = cin.Read(bytes, 0, bytes.Length);
                fstreamO.Write(bytes, 0, read);
            }
            if (slack > 0)
            {
                read = cin.Read(bytes, 0, (int)slack);
                fstreamO.Write(bytes, 0, read);
            }
            fstreamO.Flush();
            fstreamO.Close();
            fstreamO.Dispose();
            
        }

        private void btnSelectFile_Click(object sender, EventArgs e)
        {
            try
            {
                string file = textBox1.Text;

                OpenFileDialog openFileDialog1 = new OpenFileDialog();
                //openFileDialog1.Filter = "txt files (*.txt)|*.txt";

                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                    textBox1.Text = openFileDialog1.FileName;
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška\n" + exception.Message);
            }
        }

        private void btnIzracunajSazetak_Click(object sender, EventArgs e)
        {
            try
            {
                string sazetak = IzracunajSazetak(textBox1.Text);
                textBox2.Text = sazetak;
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnPotpisiFile_Click(object sender, EventArgs e)
        {
            try
            {
                string file = textBox1.Text;
                DigitalniPotpis(file);
                MessageBox.Show("File je uspješno potpisan");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnProvjeraPotpisa_Click(object sender, EventArgs e)
        {
            try
            {
                string file = textBox1.Text;
                ProvjeriDigitalniPotpis(file);
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnAKljucevi_Click(object sender, EventArgs e)
        {
            try
            {
                GenerirajAKljuceve();
                MessageBox.Show("Ključevi su generirani!");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnSKljucevi_Click(object sender, EventArgs e)
        {
            try
            {
                GenerirajSKljuc();
                MessageBox.Show("Ključ je generiran!");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnAKriptiraj_Click(object sender, EventArgs e)
        {
            try
            {
                rsaKriptiranje(textBox1.Text);
                MessageBox.Show("File je kriptiran!");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnADekriptiraj_Click(object sender, EventArgs e)
        {
            try
            {
                rsaDekriptiranje(textBox1.Text);
                MessageBox.Show("File je dekriptiran!");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnSKriptiraj_Click(object sender, EventArgs e)
        {
            try
            {
                aesKriptiranje(textBox1.Text);
                MessageBox.Show("File je kriptiran!");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }

        private void btnSDekriptiraj_Click(object sender, EventArgs e)
        {
            try
            {
                string inFile = textBox1.Text;
                int indexECB = inFile.LastIndexOf(".aes");
                string outFileECB = inFile.Substring(0, indexECB);
                aesDekriptiranje(inFile, outFileECB);
                MessageBox.Show("File je dekriptiran!");
            }
            catch (Exception exception)
            {
                MessageBox.Show("Greška!\n" + exception.Message);
            }
        }
    }
}
