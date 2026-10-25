// Google Apps Script mail relay for Secure Login Testing.
// Sends the verification emails from YOUR Gmail. Nothing else is shared with anyone.

// 1) Replace with a long random string. Use the SAME value as MAIL_WEBHOOK_SECRET on Render.
const SECRET = 'PASTE_A_LONG_RANDOM_SECRET_HERE';

function doPost(e) {
  try {
    const d = JSON.parse(e.postData.contents);

    if (d.secret !== SECRET) return reply({ ok: false, error: 'forbidden' });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(d.to || ''))) return reply({ ok: false, error: 'bad recipient' });

    // Only our own code emails can be sent, so a leaked secret can't be used as a general mailer.
    if (!String(d.subject || '').startsWith('Your Secure Login Testing code:')) return reply({ ok: false, error: 'bad subject' });
    if (String(d.message || '').length > 600) return reply({ ok: false, error: 'too long' });

    MailApp.sendEmail({
      to: d.to,
      subject: d.subject,
      body: d.message,
      name: String(d.name || 'Secure Login Testing').slice(0, 60)
    });
    return reply({ ok: true });
  } catch (err) {
    return reply({ ok: false, error: String(err) });
  }
}

function reply(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
