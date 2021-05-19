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

// SubjectAlternativeName estrutura para realizar a leitura da extensão Subject Alterantive Name OID 2.5.29.17
type SubjectAlternativeName struct {
	OtherName1 OtherName `asn1:"tag:0"`
	OtherName2 OtherName `asn1:"tag:0"`
	OtherName3 OtherName `asn1:"tag:0"`
}

// OtherName strutura para realizar a leitura dos campos otherName definidos pela ICP-Brasil contendo dados do titular do certificado
type OtherName struct {
	OID      asn1.ObjectIdentifier
	Conteudo OctetString `asn1:"tag:0"`
}

// OctetString formato ASN.1 OCTET STRING
type OctetString struct {
	Value interface{}
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
	var san SubjectAlternativeName
	if strings.Contains(cert.Subject.CommonName, ":") {
		p.Nome = strings.Split(cert.Subject.CommonName, ":")[0]
		for _, ou := range cert.Subject.OrganizationalUnit {
			if strings.Contains(ou, "e-CPF") {
				p.CPF = strings.Split(cert.Subject.CommonName, ":")[1]
			}
		}
	} else {
		p.Nome = cert.Subject.CommonName
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSAN) {
			_, err = asn1.Unmarshal(ext.Value, &san)
			break
		}
	}
	if err != nil {
		return PessoaFisica{}, err
	}

	var conteudo []byte
	var str string
	var ok bool
	switch {
	case san.OtherName1.OID.Equal(oidDadosPessoaFisica):
		conteudo, ok = san.OtherName1.Conteudo.Value.([]byte)
	case san.OtherName2.OID.Equal(oidDadosPessoaFisica):
		conteudo, ok = san.OtherName2.Conteudo.Value.([]byte)
	case san.OtherName3.OID.Equal(oidDadosPessoaFisica):
		conteudo, ok = san.OtherName3.Conteudo.Value.([]byte)
	}
	if ok {
		str = string(conteudo)
	}
	if ok && str != "" {
		p.DataNascimento, err = time.Parse("02012006", str[0:8])
		if err != nil {
			return PessoaFisica{}, err
		}
		if p.CPF == "" && str[8:19] != "00000000000" {
			p.CPF = str[8:19]
		}
		if str[19:30] != "00000000000" {
			p.NIS = str[19:30]
		}
		if str[30:45] != "000000000000000" {
			p.RG.Numero = strings.TrimLeft(str[30:45], "0")
			p.RG.UF = str[len(str)-2:]
			p.RG.OrgaoExpeditor = str[45 : len(str)-2]
		}
	}

	switch {
	case san.OtherName1.OID.Equal(oidDadosCEI):
		conteudo, ok = san.OtherName1.Conteudo.Value.([]byte)
	case san.OtherName2.OID.Equal(oidDadosCEI):
		conteudo, ok = san.OtherName2.Conteudo.Value.([]byte)
	case san.OtherName3.OID.Equal(oidDadosCEI):
		conteudo, ok = san.OtherName3.Conteudo.Value.([]byte)
	}
	str = ""
	if ok {
		str = string(conteudo)
	}
	if str != "" && str != "000000000000" {
		p.CEI = str
	}

	switch {
	case san.OtherName1.OID.Equal(oidDadosTituloEleitor):
		conteudo, ok = san.OtherName1.Conteudo.Value.([]byte)
	case san.OtherName2.OID.Equal(oidDadosTituloEleitor):
		conteudo, ok = san.OtherName2.Conteudo.Value.([]byte)
	case san.OtherName3.OID.Equal(oidDadosTituloEleitor):
		conteudo, ok = san.OtherName3.Conteudo.Value.([]byte)
	}
	str = ""
	if ok {
		str = string(conteudo)
	}
	if str != "" && str[0:12] != "000000000000" {
		p.TituloEleitor.Inscricao = str[0:12]
		p.TituloEleitor.ZonaEleitoral = str[12:15]
		p.TituloEleitor.Secao = str[15:19]
		p.TituloEleitor.UF = str[len(str)-2:]
		p.TituloEleitor.Municipio = str[19 : len(str)-2]
	}

	return p, nil
}
