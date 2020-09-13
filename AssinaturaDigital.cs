using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.IO;
using Infomed.GPS.NFSE.Entidades.Entidades;
using System.Security.Cryptography;
using Infomed.GPS.NFSE.Entidades;

namespace Infomed.GPS.NFSE.Tools {
    public class AssinaturaDigital {

        /// <summary>
        /// Realiza assinatura do XML
        /// </summary>
        /// <param name="XMLString">String do XML</param>
        /// <param name="tagPai">Tag onde terá o filho com o objeto assinatura</param>
        /// <param name="tagId">Tag que tera o campo ID a ser usado na assinatura</param>        
        /// <param name="assinaCorpoXML">Indica se o no root do XML será assinado</param>
        /// <returns>XML assinado</returns>
        public string AssinarXML(string XMLString, string tagPai, string tagId, bool assinaCorpoXML, ParametrosObtemFatura parametros) {
            X509Certificate2 X509Cert = new X509Certificate2();
            RSACryptoServiceProvider RSACert = new RSACryptoServiceProvider();

            if (parametros.TipoCert == TipoCert.A3) {
                try {
                    RSACert = ObtemRsaCertificado(parametros.TipoProvider, parametros.NomeProvider);
                } catch (Exception) {

                    throw new Exception("Nenhum certificado encontrado");
                }

            } else {
                try {
                    // Obtem o certificado digital da máquina do usuário
                    X509Cert = ObtemCertificado();
                } catch (Exception) {

                    throw new Exception("Nenhum certificado encontrado");
                }
            }

            // Cria Documento XML
            XmlDocument Documento = new XmlDocument();
            Documento.PreserveWhitespace = false;

            // XML a ser carregado
            Documento.LoadXml(XMLString);

            // Cria objeto XML a ser assinado
            SignedXml signedXml = new SignedXml(Documento);

            // Adicionar a chave privada ao XML
            signedXml.SigningKey = parametros.TipoCert == TipoCert.A1 ? X509Cert.PrivateKey : RSACert;

            // Obtem a tag onde a assimatura estara lovalizada // rps
            XmlNodeList Rps = Documento.GetElementsByTagName(tagPai);

            foreach (XmlElement ElementoRps in Rps) {
                // Obtem a tag que ira fornecer os dados para a assinatura "InfRps"
                XmlNodeList _Uri = ElementoRps.GetElementsByTagName(tagId);

                foreach (XmlElement Atributo in _Uri) {
                    // ID que ira ser a referencia para o calculo da assinatura
                    string id = Atributo.Attributes.GetNamedItem("Id").Value;
                    Reference reference = new Reference("#" + id);

                    reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                    reference.AddTransform(new XmlDsigC14NTransform());

                    // Adiciona a referencia ao objeto SignedXml
                    signedXml.AddReference(reference);

                    KeyInfo keyInfo = new KeyInfo();

                    if (parametros.TipoCert == TipoCert.A1) {
                        // Carrega os dados do Certificado a ser adicionado na assinatura
                        keyInfo.AddClause(new KeyInfoX509Data(X509Cert));
                    } else {
                        keyInfo.AddClause(new RSAKeyValue((RSA)RSACert));
                    }

                    // Adicionar os dados do certificado
                    signedXml.KeyInfo = keyInfo;

                    // Compute the signature.
                    signedXml.ComputeSignature();

                    XmlElement xmlSignature = Documento.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");
                    XmlElement xmlSignedInfo = signedXml.SignedInfo.GetXml();
                    XmlElement xmlKeyInfo = signedXml.KeyInfo.GetXml();

                    XmlElement xmlSignatureValue = Documento.CreateElement("SignatureValue", xmlSignature.NamespaceURI);
                    string signBase64 = Convert.ToBase64String(signedXml.Signature.SignatureValue);
                    XmlText text = Documento.CreateTextNode(signBase64);
                    xmlSignatureValue.AppendChild(text);

                    xmlSignature.AppendChild(Documento.ImportNode(xmlSignedInfo, true));
                    xmlSignature.AppendChild(xmlSignatureValue);
                    xmlSignature.AppendChild(Documento.ImportNode(xmlKeyInfo, true));

                    ElementoRps.AppendChild(xmlSignature);
                }
            }

            if(assinaCorpoXML)
                AssinarXML(ref Documento, parametros);
            
            return FormatXML(Documento);
        }

        /// <summary>
        /// Realiza assinatura do XML
        /// </summary>
        /// <param name="XMLString">String do XML</param>
        /// <param name="tagId">Tag que tera o campo ID a ser usado na assinatura</param>        
        /// <param name="assinaCorpoXML">Indica se o no root do XML será assinado</param>
        /// <returns>XML assinado</returns>
        public string AssinarXML(string XMLString, string tagId, bool assinaCorpoXML, ParametrosObtemFatura parametros) {
            X509Certificate2 X509Cert = new X509Certificate2();
            RSACryptoServiceProvider RSACert = new RSACryptoServiceProvider();

            if (parametros.TipoCert == TipoCert.A3) {
                try {
                    RSACert = ObtemRsaCertificado(parametros.TipoProvider, parametros.NomeProvider);
                } catch (Exception) {
                    throw new Exception("Nenhum certificado encontrado");
                }
            } else {
                try {
                    // Obtem o certificado digital da máquina do usuário
                    X509Cert = ObtemCertificado();
                } catch (Exception) {
                    throw new Exception("Nenhum certificado encontrado");
                }

            }

            // Cria Documento XML
            XmlDocument Documento = new XmlDocument();
            Documento.PreserveWhitespace = false;

            // XML a ser carregado
            Documento.LoadXml(XMLString);

            // Cria objeto XML a ser assinado
            SignedXml signedXml = new SignedXml(Documento);

            // Adicionar a chave privada ao XML
            signedXml.SigningKey = X509Cert.PrivateKey;

            // Obtem a tag que ira fornecer os dados para a assinatura "InfRps"
            XmlNodeList _Uri = Documento.GetElementsByTagName(tagId);

            foreach (XmlElement Atributo in _Uri) {
                // ID que ira ser a referencia para o calculo da assinatura
                string id = Atributo.Attributes.GetNamedItem("Id").Value;
                Reference reference = new Reference("#" + id);

                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigC14NTransform());

                // Adiciona a referencia ao objeto SignedXml
                signedXml.AddReference(reference);

                KeyInfo keyInfo = new KeyInfo();

                // Carrega os dados do Certificado a ser adicionado na assinatura
                keyInfo.AddClause(new KeyInfoX509Data(X509Cert));

                // Adicionar os dados do certificado
                signedXml.KeyInfo = keyInfo;

                signedXml.ComputeSignature();

                XmlElement xmlSignature = Documento.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");
                XmlElement xmlSignedInfo = signedXml.SignedInfo.GetXml();
                XmlElement xmlKeyInfo = signedXml.KeyInfo.GetXml();

                XmlElement xmlSignatureValue = Documento.CreateElement("SignatureValue", xmlSignature.NamespaceURI);
                string signBase64 = Convert.ToBase64String(signedXml.Signature.SignatureValue);
                XmlText text = Documento.CreateTextNode(signBase64);
                xmlSignatureValue.AppendChild(text);

                xmlSignature.AppendChild(Documento.ImportNode(xmlSignedInfo, true));
                xmlSignature.AppendChild(xmlSignatureValue);
                xmlSignature.AppendChild(Documento.ImportNode(xmlKeyInfo, true));

                Atributo.AppendChild(xmlSignature);
            }

            AssinarXML(ref Documento, parametros);
            return FormatXML(Documento);
        }

        /// <summary>
        /// Assina o corpo da mensagem XML
        /// </summary>
        /// <param name="xml">XML a ser assinado</param>
        /// <returns>XML assinado</returns>
        public string AssinarXML(string xml, ParametrosObtemFatura parametros) {
            // Cria Documento XML
            XmlDocument Documento = new XmlDocument();
            Documento.PreserveWhitespace = true;

            // XML a ser carregado
            Documento.LoadXml(xml);
            AssinarXML(ref Documento, parametros);

            return FormatXML(Documento);
        }

        /// <summary>
        /// Assina o XML por completo
        /// </summary>
        /// <param name="xmlDoc"> DOC com os dados do XML a ser assinado</param>
        private void AssinarXML(ref XmlDocument xmlDoc, ParametrosObtemFatura parametros) {
            X509Certificate2 X509Cert = new X509Certificate2();
            RSACryptoServiceProvider RSACert = new RSACryptoServiceProvider();

            if (parametros.TipoCert == TipoCert.A3) {
                RSACert = ObtemRsaCertificado(parametros.TipoProvider, parametros.NomeProvider);
            } else {
                // Obtem o certificado digital da máquina do usuário
                X509Cert = ObtemCertificado();
            }

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = parametros.TipoCert == TipoCert.A1 ? X509Cert.PrivateKey : RSACert;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Create a new KeyInfo object
            KeyInfo keyInfo = new KeyInfo();

            // Load the certificate into a KeyInfoX509Data object
            // and add it to the KeyInfo object.
            if (parametros.TipoCert == TipoCert.A1) {
                // Carrega os dados do Certificado a ser adicionado na assinatura
                keyInfo.AddClause(new KeyInfoX509Data(X509Cert));
            } else {
                keyInfo.AddClause(new RSAKeyValue((RSA)RSACert));
            }

            // Add the KeyInfo object to the SignedXml object.
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            XmlElement xmlSignature = xmlDoc.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");
            XmlElement xmlSignedInfo = signedXml.SignedInfo.GetXml();
            XmlElement xmlKeyInfo = signedXml.KeyInfo.GetXml();

            XmlElement xmlSignatureValue = xmlDoc.CreateElement("SignatureValue", xmlSignature.NamespaceURI);
            string signBase64 = Convert.ToBase64String(signedXml.Signature.SignatureValue);
            XmlText text = xmlDoc.CreateTextNode(signBase64);
            xmlSignatureValue.AppendChild(text);

            xmlSignature.AppendChild(xmlDoc.ImportNode(xmlSignedInfo, true));
            xmlSignature.AppendChild(xmlSignatureValue);
            xmlSignature.AppendChild(xmlDoc.ImportNode(xmlKeyInfo, true));

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlSignature, true));
        }

        /// <summary>
        /// Assina um XML com o certificado digital
        /// </summary>
        /// <param name="XMLString">XML a ser assinado</param>
        /// <param name="RefUri">Referência da URI a ser assinada Ex.: ConsultarSituacaoLoteRpsEnvio</param>
        /// <returns>XML assinado</returns>
        public string AssinarXML(string XMLString, string RefUri, ParametrosObtemFatura parametros) {
            X509Certificate2 X509Cert = new X509Certificate2();
            RSACryptoServiceProvider RSACert = new RSACryptoServiceProvider();
            X509Certificate2 _X509Cert = new X509Certificate2();

            if (parametros.TipoCert == TipoCert.A3) {
                RSACert = ObtemRsaCertificado(parametros.TipoProvider, parametros.NomeProvider);
            } else {
                // Obtem o certificado digital da máquina do usuário
                X509Cert = ObtemCertificado();
            }

            string Resultado = string.Empty;
            try {
                string Xnome = "";

                if (parametros.TipoCert == TipoCert.A1) {
                    Xnome = X509Cert.Subject.ToString();

                    X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                    X509Certificate2Collection collection1 = (X509Certificate2Collection)collection.Find(X509FindType.FindBySubjectDistinguishedName, Xnome, false);

                    if (collection1.Count == 0) {
                        throw new Exception("Problemas no certificado digital");
                    } else {
                        // certificado ok
                        _X509Cert = collection1[0];
                        string KeyAlgorithm;
                        KeyAlgorithm = _X509Cert.GetKeyAlgorithm().ToString();
                    }
                }

                // Create a new XML document.
                XmlDocument doc = new XmlDocument();

                // Format the document to ignore white spaces.
                doc.PreserveWhitespace = false;

                // Load the passed XML file using it's name.
                try {
                    doc.LoadXml(XMLString);

                    // Verifica se a tag a ser assinada existe é única
                    int qtdeRefUri = doc.GetElementsByTagName(RefUri).Count;

                    if (qtdeRefUri == 0) {
                        // a URI indicada não existe
                        throw new Exception("A tag de assinatura %RefUri% inexiste");
                    }
                        // Exsiste mais de uma tag a ser assinada
                    else {
                        if (qtdeRefUri > 1) {
                            // existe mais de uma URI indicada
                            throw new Exception("A tag de assinatura %RefUri% não é unica");
                        } else {
                            try {

                                // Create a SignedXml object.
                                SignedXml signedXml = new SignedXml(doc);

                                // Add the key to the SignedXml document 
                                signedXml.SigningKey = parametros.TipoCert == TipoCert.A1 ? _X509Cert.PrivateKey : RSACert;

                                // Create a reference to be signed
                                Reference reference = new Reference();
                                // pega o uri que deve ser assinada
                                XmlAttributeCollection _Uri = doc.GetElementsByTagName(RefUri).Item(0).Attributes;
                                reference.Uri = "";

                                // Add an enveloped transformation to the reference.
                                XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                                reference.AddTransform(env);

                                XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
                                reference.AddTransform(c14);

                                // Add the reference to the SignedXml object.
                                signedXml.AddReference(reference);

                                // Create a new KeyInfo object
                                KeyInfo keyInfo = new KeyInfo();

                                // Load the certificate into a KeyInfoX509Data object
                                // and add it to the KeyInfo object.
                                if (parametros.TipoCert == TipoCert.A1) {
                                    // Carrega os dados do Certificado a ser adicionado na assinatura
                                    keyInfo.AddClause(new KeyInfoX509Data(_X509Cert));
                                } else {
                                    keyInfo.AddClause(new RSAKeyValue((RSA)RSACert));
                                }

                                // Add the KeyInfo object to the SignedXml object.
                                signedXml.KeyInfo = keyInfo;

                                signedXml.ComputeSignature();

                                // Get the XML representation of the signature and save
                                // it to an XmlElement object.
                                XmlElement xmlDigitalSignature = signedXml.GetXml();

                                // Append the element to the XML document.
                                doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                XmlDocument XMLDoc = new XmlDocument();
                                XMLDoc.PreserveWhitespace = false;
                                XMLDoc = doc;
                                Resultado = doc.OuterXml;
                            } catch (Exception caught) {
                                System.Console.WriteLine(caught.Message);
                                throw new Exception("Erro Ao assinar o documento - ID deve ser string %RefUri(Atributo)%");
                            }
                        }
                    }
                } catch (Exception E) {
                    throw new Exception(E.Message);
                }

            } catch (Exception E) {
                throw new Exception(E.Message);
            }

            return Resultado;
        }

        /// <summary>
        /// Assina um XML com o certificado digital
        /// </summary>
        /// <param name="XMLString">XML a ser assinado</param>
        /// <param name="RefUri">Referência da URI a ser assinada Ex.: ConsultarSituacaoLoteRpsEnvio</param>
        /// <param name="putInsideRef">Indica se a assinatura deverá ficar no elemento do RefUri</param>
        /// <param name="parametros">Parametros para configurar a fatura</param>
        /// <returns>XML assinado</returns>
        public string AssinarXMLInner(string XMLString, string RefUri, bool putInsideRef, ParametrosObtemFatura parametros) {
            X509Certificate2 X509Cert = new X509Certificate2();
            RSACryptoServiceProvider RSACert = new RSACryptoServiceProvider();
            X509Certificate2 _X509Cert = new X509Certificate2();

            if (parametros.TipoCert == TipoCert.A3) {
                RSACert = ObtemRsaCertificado(parametros.TipoProvider, parametros.NomeProvider);
            } else {
                // Obtem o certificado digital da máquina do usuário
                X509Cert = ObtemCertificado();
            }

            string Resultado = string.Empty;
            try {
                string Xnome = "";

                if (parametros.TipoCert == TipoCert.A1) {
                    Xnome = X509Cert.Subject.ToString();

                    X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                    X509Certificate2Collection collection1 = (X509Certificate2Collection)collection.Find(X509FindType.FindBySubjectDistinguishedName, Xnome, false);

                    if (collection1.Count == 0) {
                        throw new Exception("Problemas no certificado digital");
                    } else {
                        // certificado ok
                        _X509Cert = collection1[0];
                        string KeyAlgorithm;
                        KeyAlgorithm = _X509Cert.GetKeyAlgorithm().ToString();
                    }
                }

                // Create a new XML document.
                XmlDocument doc = new XmlDocument();

                // Format the document to ignore white spaces.
                doc.PreserveWhitespace = false;

                // Load the passed XML file using it's name.
                try {
                    doc.LoadXml(XMLString);

                    // Verifica se a tag a ser assinada existe é única
                    int qtdeRefUri = doc.GetElementsByTagName(RefUri).Count;

                    if (qtdeRefUri == 0) {
                        // a URI indicada não existe
                        throw new Exception("A tag de assinatura %RefUri% inexiste");
                    }
                        // Exsiste mais de uma tag a ser assinada
                    else {
                        if (qtdeRefUri > 1) {
                            // existe mais de uma URI indicada
                            throw new Exception("A tag de assinatura %RefUri% não é unica");
                        } else {
                            try {

                                // Create a SignedXml object.
                                SignedXml signedXml = new SignedXml(doc);

                                // Add the key to the SignedXml document 
                                signedXml.SigningKey = parametros.TipoCert == TipoCert.A1 ? _X509Cert.PrivateKey : RSACert;

                                // Create a reference to be signed
                                Reference reference = new Reference();
                                // pega o uri que deve ser assinada
                                XmlAttributeCollection _Uri = doc.GetElementsByTagName(RefUri).Item(0).Attributes;
                                reference.Uri = "";

                                // Add an enveloped transformation to the reference.
                                XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                                reference.AddTransform(env);

                                XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
                                reference.AddTransform(c14);

                                // Add the reference to the SignedXml object.
                                signedXml.AddReference(reference);

                                // Create a new KeyInfo object
                                KeyInfo keyInfo = new KeyInfo();

                                // Load the certificate into a KeyInfoX509Data object
                                // and add it to the KeyInfo object.
                                if (parametros.TipoCert == TipoCert.A1) {
                                    // Carrega os dados do Certificado a ser adicionado na assinatura
                                    keyInfo.AddClause(new KeyInfoX509Data(_X509Cert));
                                } else {
                                    keyInfo.AddClause(new RSAKeyValue((RSA)RSACert));
                                }

                                // Add the KeyInfo object to the SignedXml object.
                                signedXml.KeyInfo = keyInfo;

                                signedXml.ComputeSignature();

                                // Get the XML representation of the signature and save
                                // it to an XmlElement object.
                                XmlElement xmlDigitalSignature = signedXml.GetXml();
                                if (!putInsideRef)
                                    // Append the element to the XML document.
                                    doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                else {
                                    doc.GetElementsByTagName(RefUri).Item(0).AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                                }

                                XmlDocument XMLDoc = new XmlDocument();
                                XMLDoc.PreserveWhitespace = false;
                                XMLDoc = doc;
                                Resultado = doc.OuterXml;
                            } catch (Exception caught) {
                                System.Console.WriteLine(caught.Message);
                                throw new Exception("Erro Ao assinar o documento - ID deve ser string %RefUri(Atributo)%");
                            }
                        }
                    }
                } catch (Exception E) {
                    throw new Exception(E.Message);
                }

            } catch (Exception E) {
                throw new Exception(E.Message);
            }

            return Resultado;
        }

        /// <summary>
        /// Formata do MXL para ficar com as identações corretas
        /// </summary>
        /// <param name="doc">DOC a ser formatado</param>
        /// <returns></returns>
        private string FormatXML(XmlDocument doc) {
            // Create a stream buffer that can be read as a string
            using (StringWriter sw = new StringWriter())

            // Create a specialized writer for XML code
            using (XmlTextWriter xtw = new XmlTextWriter(sw)) {
                // Set the writer to use indented (hierarchical) elements
                xtw.Formatting = System.Xml.Formatting.Indented;

                // Write the XML document to the stream
                doc.WriteTo(xtw);

                // Return the stream as a string
                return sw.ToString();
            }
        }

        /// <summary>
        /// Obtem os certificados com chave privada da máquina do usuário
        /// </summary>
        /// <returns>Certificado encontrado</returns>
        public X509Certificate2 ObtemCertificado() {
            X509Store lStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            X509Certificate2 Cert = new X509Certificate2();
            // Abre o Store
            lStore.Open(OpenFlags.ReadOnly);

            // Lista os certificados
            var lcerts = lStore.Certificates;

            foreach (X509Certificate2 cert in lcerts) {
                if (cert.HasPrivateKey && cert.NotAfter > DateTime.Now && cert.NotBefore < DateTime.Now) {
                    Cert = cert;
                }
            }
            lStore.Close();

            return Cert;
        }

        /// <summary>
        /// Obtem os certificados com chave privada da leitora de cartões instalada na máquina do usuário
        /// </summary>
        /// <returns>Certificado encontrado</returns>
        public RSACryptoServiceProvider ObtemRsaCertificado(string tipoProvider, string nomeProvider) {
            //CspParameters csp = new CspParameters(1, "SafeSign Standard Cryptographic Service Provider");
            CspParameters csp = new CspParameters(int.Parse(tipoProvider), nomeProvider);
            csp.Flags = CspProviderFlags.UseDefaultKeyContainer;
            return new RSACryptoServiceProvider(csp);
        }

        /// <summary>
        /// Caso esteja utilizando certificado do tipo A3, é necessário chamar esse método para obtenção desse certificado.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 ObtemCertificadoA3() {
            X509Certificate2 x509Certificate = new X509Certificate2();
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            //  X509Certificate2Collection collection1 = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
            X509Certificate2Collection collection2 = (X509Certificate2Collection)collection.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, false);
            X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(collection2, "Certificado(s) Digital(is) disponível(is)", "Selecione o certificado digital para uso no aplicativo", X509SelectionFlag.SingleSelection);

            return scollection[0];
        }
    }
}
