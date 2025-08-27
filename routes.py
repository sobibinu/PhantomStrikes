import os
import logging
import json
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_file, Response, current_app
from flask_login import login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from models import ScanResult, Vulnerability, User
from app import db
from vulnerability_scanner import VulnerabilityScanner, get_scan_result, get_scan_results_for_user, get_guest_scans, sanitize_target_url
import tempfile
import csv
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)
main = Blueprint('main', __name__)

@main.route('/')
def index():
    # Get recent guest scans for the homepage
    recent_scans = get_guest_scans(5)
    
    return render_template('index.html', recent_scans=recent_scans)

@main.route('/dashboard')
@login_required
def dashboard():
    # Get user's scan history
    user_scans = get_scan_results_for_user(current_user.id, 10)
    
    return render_template('dashboard.html', scans=user_scans)

@main.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        # Get form data
        target_url = request.form.get('target_url')
        scan_type = request.form.get('scan_type', 'light')
        
        if not target_url:
            flash('Please enter a target URL', 'danger')
            return redirect(url_for('main.scan'))
        
        # Check if user is authenticated
        user_id = current_user.id if current_user.is_authenticated else None
        
        # For non-authenticated users, only allow 'light' scan
        if not user_id and scan_type != 'light':
            flash('Guest users can only perform light scans. Please log in for advanced scan options.', 'warning')
            scan_type = 'light'
        
        # Check if scan type is valid
        valid_scan_types = ['light', 'medium', 'deep', 'network']
        if scan_type not in valid_scan_types:
            flash('Invalid scan type', 'danger')
            return redirect(url_for('main.scan'))
        
        # Validate and sanitize target URL
        try:
            target_url = sanitize_target_url(target_url)
        except ValueError as e:
            flash(f'Invalid URL: {str(e)}', 'danger')
            return redirect(url_for('main.scan'))
        
        # Create scan configuration
        scan_config = {
            'custom_options': request.form.get('custom_options', ''),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Initialize scanner
            scanner = VulnerabilityScanner(target_url, scan_type, user_id)
            
            # Start scan
            scan_id = scanner.start_scan(scan_config)
            
            flash(f'Scan started successfully! Scan ID: {scan_id}', 'success')
            return redirect(url_for('main.scan_result', scan_id=scan_id))
            
        except Exception as e:
            logger.exception(f"Error starting scan: {str(e)}")
            flash(f'Error starting scan: {str(e)}', 'danger')
            return redirect(url_for('main.scan'))
    
    # For GET request, show scan form
    return render_template('scan.html')

@main.route('/scan_result/<int:scan_id>')
def scan_result(scan_id):
    # Check if user is authenticated to determine access level
    is_authenticated = current_user.is_authenticated
    
    # Get scan result with appropriate access level
    result = get_scan_result(scan_id, is_authenticated)
    
    if not result:
        flash('Scan result not found', 'danger')
        return redirect(url_for('main.index'))
    
    # Check if the result belongs to a specific user
    if 'user_id' in result and result['user_id'] is not None:
        # If authenticated but not the owner, restrict access
        if is_authenticated and result['user_id'] != current_user.id:
            flash('You do not have permission to view this scan result', 'danger')
            return redirect(url_for('main.dashboard'))
    
    return render_template('scan_result.html', scan=result, is_authenticated=is_authenticated)

@main.route('/api/scan/status/<int:scan_id>')
def scan_status(scan_id):
    # Get scan result with appropriate access level
    is_authenticated = current_user.is_authenticated
    result = get_scan_result(scan_id, is_authenticated)
    
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'id': result['id'],
        'status': result['status'],
        'total_vulnerabilities': result.get('total_vulnerabilities', 0),
        'high_severity': result.get('high_severity', 0),
        'medium_severity': result.get('medium_severity', 0),
        'low_severity': result.get('low_severity', 0)
    })

@main.route('/api/scan/result/<int:scan_id>')
def api_scan_result(scan_id):
    # Check if user is authenticated to determine access level
    is_authenticated = current_user.is_authenticated
    
    # Get scan result with appropriate access level
    result = get_scan_result(scan_id, is_authenticated)
    
    if not result:
        return jsonify({'error': 'Scan result not found'}), 404
    
    return jsonify(result)

@main.route('/export/<int:scan_id>/<format>')
@login_required
def export_result(scan_id, format):
    # Verify the scan exists and user has access
    scan_result = ScanResult.query.get(scan_id)
    
    if not scan_result:
        flash('Scan result not found', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Check if user has access (either their scan or a guest scan)
    if scan_result.user_id is not None and scan_result.user_id != current_user.id:
        flash('You do not have permission to export this scan result', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if format == 'json':
        # Convert to JSON
        result_dict = scan_result.to_dict()
        result_json = json.dumps(result_dict, indent=2)
        
        # Create a response with the JSON data
        response = Response(
            result_json,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment;filename=scan_result_{scan_id}.json'
            }
        )
        return response
    
    elif format == 'csv':
        # Create a CSV file in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Type', 'Severity', 'Location', 'Description', 'Evidence', 'Remediation'])
        
        # Write vulnerability data
        for vuln in scan_result.vulnerabilities:
            writer.writerow([
                vuln.vulnerability_type,
                vuln.severity,
                vuln.location,
                vuln.description,
                vuln.evidence,
                vuln.remediation
            ])
        
        # Create a response with the CSV data
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment;filename=scan_result_{scan_id}.csv'
            }
        )
    
    elif format == 'pdf':
        # Create PDF report
        buffer = io.BytesIO()
        
        # Create the PDF object using ReportLab
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Add title
        title_style = styles['Heading1']
        elements.append(Paragraph(f"Vulnerability Scan Report", title_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        # Add scan information
        scan_info_style = styles['Normal']
        elements.append(Paragraph(f"Target URL: {scan_result.target_url}", scan_info_style))
        elements.append(Paragraph(f"Scan Type: {scan_result.scan_type}", scan_info_style))
        elements.append(Paragraph(f"Scan Date: {scan_result.start_time.strftime('%Y-%m-%d %H:%M UTC') if scan_result.start_time else 'N/A'}", scan_info_style))
        elements.append(Paragraph(f"Total Vulnerabilities: {scan_result.total_vulnerabilities}", scan_info_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        # Add summary of vulnerabilities by severity
        elements.append(Paragraph("Severity Summary:", styles['Heading2']))
        data = [
            ["High", "Medium", "Low"],
            [str(scan_result.high_severity), str(scan_result.medium_severity), str(scan_result.low_severity)]
        ]
        
        table = Table(data, colWidths=[2*inch, 2*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (2, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (2, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (2, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (2, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (2, 0), 14),
            ('BOTTOMPADDING', (0, 0), (2, 0), 12),
            ('BACKGROUND', (0, 1), (0, 1), colors.pink),
            ('BACKGROUND', (1, 1), (1, 1), colors.lightblue),
            ('BACKGROUND', (2, 1), (2, 1), colors.lightgreen),
            ('ALIGN', (0, 1), (2, 1), 'CENTER'),
            ('FONTNAME', (0, 1), (2, 1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (2, 1), 12),
            ('GRID', (0, 0), (2, 1), 1, colors.black)
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.5 * inch))
        
        # Add vulnerability details
        elements.append(Paragraph("Vulnerability Details:", styles['Heading2']))
        elements.append(Spacer(1, 0.1 * inch))
        
        # Create a style for vulnerability titles
        vuln_title_style = ParagraphStyle(
            'VulnTitle',
            parent=styles['Heading3'],
            backColor=colors.lightgrey,
            borderColor=colors.black,
            borderWidth=1,
            borderPadding=5,
            spaceBefore=10,
            spaceAfter=5
        )
        
        # Add each vulnerability
        for vuln in scan_result.vulnerabilities:
            # Add severity color
            if vuln.severity.lower() == 'high':
                color_code = colors.pink
            elif vuln.severity.lower() == 'medium':
                color_code = colors.lightblue
            else:
                color_code = colors.lightgreen
                
            # Vulnerability type and severity
            elements.append(Paragraph(
                f"{vuln.vulnerability_type} - {vuln.severity.upper()}", 
                vuln_title_style
            ))
            
            # Details table
            data = [
                ["Location", vuln.location],
                ["Description", vuln.description],
                ["Evidence", vuln.evidence],
                ["Remediation", vuln.remediation]
            ]
            
            if vuln.remediation_code:
                data.append(["Example Code", vuln.remediation_code])
            
            detail_table = Table(data, colWidths=[1.5*inch, 4.5*inch])
            detail_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('WORDWRAP', (1, 0), (1, -1), True),
            ]))
            
            elements.append(detail_table)
            elements.append(Spacer(1, 0.2 * inch))
        
        # Build the PDF
        doc.build(elements)
        
        # Get the value from the BytesIO buffer and create the response
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment;filename=scan_result_{scan_id}.pdf'
            }
        )
    
    else:
        flash('Invalid export format', 'danger')
        return redirect(url_for('main.scan_result', scan_id=scan_id))

@main.route('/api/scan/start', methods=['POST'])
@jwt_required()
def api_start_scan():
    user_id = get_jwt_identity()
    
    # Get JSON data
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON data'}), 400
    
    target_url = data.get('target_url')
    scan_type = data.get('scan_type', 'light')
    
    if not target_url:
        return jsonify({'error': 'Missing target URL'}), 400
    
    # Validate scan type
    valid_scan_types = ['light', 'medium', 'deep', 'network']
    if scan_type not in valid_scan_types:
        return jsonify({'error': 'Invalid scan type'}), 400
    
    # Validate and sanitize target URL
    try:
        target_url = sanitize_target_url(target_url)
    except ValueError as e:
        return jsonify({'error': f'Invalid URL: {str(e)}'}), 400
    
    # Create scan configuration
    scan_config = {
        'custom_options': data.get('custom_options', ''),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner(target_url, scan_type, user_id)
        
        # Start scan
        scan_id = scanner.start_scan(scan_config)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.exception(f"Error starting scan: {str(e)}")
        return jsonify({'error': f'Error starting scan: {str(e)}'}), 500
