
rule Ransomware_Indicators
{
    meta:
        description = "Ransomware behavior indicators"
    
    strings:
        $r1 = "encrypt" nocase
        $r2 = "decrypt" nocase
        $r3 = "bitcoin" nocase
        $r4 = "ransom" nocase
        $r5 = ".locked"
        $r6 = ".encrypted"
    
    condition:
        2 of them
}
