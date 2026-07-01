$word = New-Object -ComObject Word.Application
$word.Visible = $false
$doc = $word.Documents.Open('c:\Users\nayan\OneDrive\Desktop\NJ_PROJ\photon\Photon_Security_Design_Document.docx')
$text = $doc.Content.Text
$doc.Close([ref]$false)
$word.Quit()
$text | Out-File -FilePath 'c:\Users\nayan\OneDrive\Desktop\NJ_PROJ\photon\design_doc_text.txt' -Encoding UTF8
