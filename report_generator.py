from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

def generate_report(filename, data):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    
    styles = getSampleStyleSheet()
    elements.append(Paragraph("Network Traffic Analysis Report", styles['Title']))
    
    # Top IPs
    elements.append(Paragraph("Top IPs", styles['Heading2']))
    top_ips_data = [["IP", "Count", "Country", "City"]]
    for ip, count in data['top_ips']:
        location = data.get('geolocation', {}).get(ip, {})
        country = location.get('country', 'Unknown')
        city = location.get('city', 'Unknown')
        top_ips_data.append([ip, count, country, city])
    
    top_ips_table = Table(top_ips_data)
    top_ips_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(top_ips_table)
    
    # Protocol Distribution
    elements.append(Paragraph("Protocol Distribution", styles['Heading2']))
    proto_data = [["Protocol", "Count"]] + list(data['protocol_distribution'].items())
    proto_table = Table(proto_data)
    proto_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(proto_table)

    # Total Bytes
    elements.append(Paragraph(f"Total Bytes Transferred: {data['total_bytes']}", styles['Normal']))

    # Anomalies
    elements.append(Paragraph("Detected Anomalies", styles['Heading2']))
    if data['anomalies']:
        anomalies_text = '\n'.join([f"{ip}: {count}" for ip, count in data['anomalies']])
        elements.append(Paragraph(anomalies_text, styles['Normal']))
    else:
        elements.append(Paragraph("No anomalies detected.", styles['Normal']))

    doc.build(elements)