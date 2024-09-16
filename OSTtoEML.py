# Stuart's code to extract emails from a PST or OST file
# Recurses folders in PST file
# creates an EML file from any message or item that contains a message transport header
# source and destination definitions at the bottom of the code

import pypff
import os
from email import message_from_string
from email.policy import default
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import decode_header
from email import encoders
import magic


# Constants for truncation limits
MAX_FILENAME_LENGTH = 255
MAX_SUBJECT_LENGTH = 100
MAX_FOLDER_NAME_LENGTH = 100

def decode_header_value(header_value):
    """Decodes a MIME header to handle encoded words."""
    decoded_parts = decode_header(header_value)
    decoded_header = ''
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            if encoding is not None:
                decoded_header += part.decode(encoding, errors='ignore')
            else:
                decoded_header += part.decode('utf-8', errors='ignore')
        else:
            decoded_header += part
    return decoded_header

def get_email_addresses(header_value):
    """Extracts email addresses from a header string."""
    return decode_header_value(header_value).strip()

def extract_header_info(message):
    headers = message.transport_headers or ""

    # Parse the headers using the email module
    if headers:
        parsed_headers = message_from_string(headers, policy=default)
        subject = decode_header_value(parsed_headers.get('Subject', 'No Subject'))
        from_address = get_email_addresses(parsed_headers.get('From', 'Unknown Sender'))
        to_address = get_email_addresses(parsed_headers.get('To', 'Unknown Recipient'))
    else:
        subject = message.get_subject() or 'No Subject'
        from_address = message.get_sender_name() or 'Unknown Sender'
        to_address = 'Unknown Recipient'

    return subject, from_address, to_address

def construct_eml_with_attachments(message):
    subject, from_address, to_address = extract_header_info(message)
    
    plain_text_body = message.get_plain_text_body()
    html_body = message.get_html_body()
    rtf_body = message.get_rtf_body()

    # Decode if the content is in bytes
    if plain_text_body:
        plain_text_body = plain_text_body.decode('utf-8', errors='ignore')
    if html_body:
        html_body = html_body.decode('utf-8', errors='ignore')
    if rtf_body:
        rtf_body = rtf_body.decode('utf-8', errors='ignore')

    message_body = html_body or plain_text_body or rtf_body

    # Create MIME multipart message
    eml_msg = MIMEMultipart()
    eml_msg['Subject'] = subject
    eml_msg['From'] = from_address
    eml_msg['To'] = to_address
    
    # Add the message body (as plain text or HTML)
    if html_body:
        eml_msg.attach(MIMEText(html_body, 'html'))
    else:
        eml_msg.attach(MIMEText(plain_text_body or rtf_body, 'plain'))

    # Handle attachments
    mime = magic.Magic(mime=True)  # Initialize the magic object to detect mime types
    attachment_name = "not found"
    try:
        for i in range(message.number_of_attachments):
            attachment = message.get_attachment(i)
            try:
                attachment_name = attachment.get_long_filename() or attachment.get_short_filename() or f"attachment_{i+1}"
            except AttributeError:
                attachment_name = f"attachment_{i+1}"

            attachment_data = attachment.read_buffer(attachment.get_size())

            # Detect MIME type
            mime_type = mime.from_buffer(attachment_data)
            mime_main, mime_subtype = mime_type.split("/")

            # Create a MIMEBase object to handle the attachment
            mime_attachment = MIMEBase(mime_main, mime_subtype)
            mime_attachment.set_payload(attachment_data)

            attachment_name += "." + mime_subtype
            # Encode the attachment in base64
            encoders.encode_base64(mime_attachment)
            mime_attachment.add_header('Content-Disposition', f'attachment; filename="{attachment_name}"')

            # Attach the file to the message
            eml_msg.attach(mime_attachment)
    except Exception as e:
        print(f"  Error processing {attachment_name}: {e}")
    
    return eml_msg.as_string()

def truncate_string(input_string, max_length):
    """Truncate a string to a specified maximum length."""
    return input_string[:max_length] if len(input_string) > max_length else input_string

def sanitize_and_truncate_filename(subject, folder_name, message_index):
    """Sanitize and truncate the subject and folder name to ensure it doesn't exceed filename length limits."""
    subject_sanitized = "".join([c if c.isalnum() else "_" for c in subject])
    subject_truncated = truncate_string(subject_sanitized, MAX_SUBJECT_LENGTH)
    
    folder_name_sanitized = "".join([c if c.isalnum() else "_" for c in folder_name])
    folder_name_truncated = truncate_string(folder_name_sanitized, MAX_FOLDER_NAME_LENGTH)

    eml_filename = f"message_{message_index}_{subject_truncated}.eml"
    
    # Ensure filename doesn't exceed the maximum allowed filename length
    return truncate_string(eml_filename, MAX_FILENAME_LENGTH), folder_name_truncated

def save_message_as_eml(message, output_dir, folder_name, message_index):
    try:
        subject, from_address, to_address = extract_header_info(message)

        # Get a sanitized and truncated filename
        eml_filename, folder_name_sanitized = sanitize_and_truncate_filename(subject, folder_name, message_index)
        
        folder_path = os.path.join(output_dir, folder_name_sanitized)
        os.makedirs(folder_path, exist_ok=True)

        eml_path = os.path.join(folder_path, eml_filename)

        eml_data = construct_eml_with_attachments(message)
        with open(eml_path, 'w', encoding='utf-8') as eml_file:
            eml_file.write(eml_data)

        print(f"  Saved message as {eml_filename}")
    except Exception as e:
        print(f"  Error saving message {message_index}: {e}")

def process_folder(folder, output_dir):
    folder_name = folder.name or 'No_Name'
    print(f"Processing folder: {folder_name}")
    if folder_name=="Inbox":
        print("skipping Inbox")
    else:
        try:
            numsub= folder.get_number_of_sub_messages()
        except Exception as e:
            numsub=0
            print(f"  Error - no sub messages in folder: {folder}") 
        for i in range(numsub):
            try:
                message =folder.get_sub_message(i)
                save_message_as_eml(message, output_dir, folder_name, i)
            except Exception as e:
                print(f"  Error saving message {i}: {e}") 
    for subfolder in folder.sub_folders:
        process_folder(subfolder, output_dir)

def extract_emls_from_ost(ost_file_path, output_dir):
    print(f"Opening OST file: {ost_file_path}")
    ost_file = pypff.file()
    ost_file.open(ost_file_path)

    print(f"Getting root folder")
    root_folder = ost_file.get_root_folder()

    print(f"Starting to process the folders")
    process_folder(root_folder, output_dir)

    ost_file.close()
    print("Finished processing OST file")

# Usage example
ost_file_path = "F:\\jtemp\\new.pst"  # Replace with your OST file path
output_dir = "F:\\jtemp\\eml_files"  # Directory where EML files will be saved
os.makedirs(output_dir, exist_ok=True)
extract_emls_from_ost(ost_file_path, output_dir)
