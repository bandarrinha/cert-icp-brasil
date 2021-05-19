package certICPBrasil

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"time"
)

var (
	oidSAN                = []int{2, 5, 29, 17}
	oidDadosPessoaFisica  = []int{2, 16, 76, 1, 3, 1}
	oidDadosCEI           = []int{2, 16, 76, 1, 3, 6}
	oidDadosTituloEleitor = []int{2, 16, 76, 1, 3, 5}
)

// OtherName strutura para realizar a leitura dos campos otherName definidos pela ICP-Brasil contendo dados do titular do certificado
type OtherName struct {
	OID      asn1.ObjectIdentifier
	Conteudo `asn1:"tag:0"`
}

type Conteudo struct {
	Valor interface{}
}

// PessoaFisica estrutura que representa os dados de uma pessoa física contidos em um certificado icp-brasil
type PessoaFisica struct {
	Nome           string
	DataNascimento time.Time
	CPF            string
	NIS            string
	RG             RegistroGeral
	CEI            string
	TituloEleitor  TituloEleitor
	Email          string
}

// TituloEleitor estrutura que representa os dados do Título de Eleitor
type TituloEleitor struct {
	Inscricao     string
	ZonaEleitoral string
	Secao         string
	Municipio     string
	UF            string
}

// RegistroGeral estrutura que representa os dados do RG - Registro Geral de identificação cívil
type RegistroGeral struct {
	Numero         string
	OrgaoExpeditor string
	UF             string
}

// ParseDadosPessoaFisicaFromCertificado função que extrai os dados do titular de um certificado ICP-Brasil Pessoa Física
func ParseDadosPessoaFisicaFromCertificado(cert *x509.Certificate) (p PessoaFisica, err error) {
	var san asn1.RawValue
	if strings.Contains(cert.Subject.CommonName, ":") {
		p.Nome = strings.Split(cert.Subject.CommonName, ":")[0]
		for _, ou := range cert.Subject.OrganizationalUnit {
			if strings.Contains(ou, "e-CPF") {
				p.CPF = strings.Split(cert.Subject.CommonName, ":")[1]
				break
			}
		}
	} else {
		p.Nome = cert.Subject.CommonName
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSAN) {
			_, err = asn1.Unmarshal(ext.Value, &san)
			if err != nil {
				return PessoaFisica{}, err
			}
			rest := san.Bytes
			for len(rest) > 0 && err == nil {
				rest, err = asn1.Unmarshal(rest, &san)
				switch san.Tag {
				case 0:
					var otherName OtherName
					_, err := asn1.UnmarshalWithParams(san.FullBytes, &otherName, "tag:0")
					if err != nil {
						return PessoaFisica{}, err
					}
					var valor string
					switch otherName.Conteudo.Valor.(type) {
					case []byte:
						valor = string(otherName.Conteudo.Valor.([]byte))
					case string:
						valor = otherName.Conteudo.Valor.(string)
					}
					if valor != "" {
						conteudo := string(valor)
						switch {
						case otherName.OID.Equal(oidDadosPessoaFisica):
							p.DataNascimento, err = time.Parse("02012006", conteudo[0:8])
							if err != nil {
								return PessoaFisica{}, err
							}
							if p.CPF == "" && conteudo[8:19] != "00000000000" {
								p.CPF = conteudo[8:19]
							}
							if conteudo[19:30] != "00000000000" {
								p.NIS = conteudo[19:30]
							}
							if conteudo[30:45] != "000000000000000" {
								p.RG.Numero = strings.TrimLeft(conteudo[30:45], "0")
								p.RG.UF = conteudo[len(conteudo)-2:]
								p.RG.OrgaoExpeditor = conteudo[45 : len(conteudo)-2]
							}
						case otherName.OID.Equal(oidDadosCEI):
							if conteudo != "000000000000" {
								p.CEI = conteudo
							}
						case otherName.OID.Equal(oidDadosTituloEleitor):
							if conteudo[0:12] != "000000000000" {
								p.TituloEleitor.Inscricao = conteudo[0:12]
								p.TituloEleitor.ZonaEleitoral = conteudo[12:15]
								p.TituloEleitor.Secao = conteudo[15:19]
								p.TituloEleitor.UF = conteudo[len(conteudo)-2:]
								p.TituloEleitor.Municipio = conteudo[19 : len(conteudo)-2]
							}
						}
					}
				case 1:
					_, err = asn1.UnmarshalWithParams(san.FullBytes, &p.Email, "tag:1,ia5")
					if err != nil {
						return PessoaFisica{}, err
					}
				}
			}

		}
	}
	if err != nil {
		return PessoaFisica{}, err
	}
	return p, nil
}
