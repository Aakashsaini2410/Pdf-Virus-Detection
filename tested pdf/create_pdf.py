from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def create_test_pdf(filename):
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "This is a test PDF with a simulated virus.")
    c.drawString(100, 735, "Virus Simulation: EICAR")
    c.save()

create_test_pdf("malicious_test.pdf")
