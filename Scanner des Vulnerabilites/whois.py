import whois
from datetime import datetime, timedelta

def fetch_whois_info(domain):
    w = whois.whois(domain)
    return w

def format_whois_info(w):
    now = datetime.utcnow()
    expires_in = (w.expiration_date - now) if w.expiration_date else 'Unknown'
    
    if isinstance(expires_in, timedelta):
        days, seconds = expires_in.days, expires_in.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        expires_in_str = f"{hours} hours, {minutes} minutes and {seconds} seconds"
    else:
        expires_in_str = 'Unknown'

    formatted_info = f"""
    WHOIS information for {w.domain_name}
    Cache expires in {expires_in_str}
    
    Registrar Info
    Name: {w.registrar}
    Status: {'Active' if w.status else 'Inactive'}
    
    Important Dates
    Expires On: {w.expiration_date if w.expiration_date else 'Unknown'}
    Registered On: {w.creation_date if w.creation_date else 'Unknown'}
    Updated On: {w.updated_date if w.updated_date else 'Unknown'}
    
    Similar Domains
    {' | '.join(w.domain_name) if isinstance(w.domain_name, list) else w.domain_name}
    
    Registrar Data
    domain:                        {w.domain_name}
    status:                        {w.status if w.status else 'Unknown'}
    hold:                          {'NO' if w.status == 'active' else 'YES'}
    registrar:                     {w.registrar}
    Expiry Date:                   {w.expiration_date if w.expiration_date else 'Unknown'}
    created:                       {w.creation_date if w.creation_date else 'Unknown'}
    last-update:                   {w.updated_date if w.updated_date else 'Unknown'}
    source:                        WHOIS
    nserver:                       {' | '.join(w.name_servers) if w.name_servers else 'Unknown'}
    source:                        WHOIS
    registrar:                     {w.registrar}
    address:                       {w.registrar_address if w.registrar_address else 'Unknown'}
    country:                       {w.registrar_country if w.registrar_country else 'Unknown'}
    phone:                         {w.registrar_phone if w.registrar_phone else 'Unknown'}
    e-mail:                        {w.registrar_email if w.registrar_email else 'Unknown'}
    website:                       {w.registrar_url if w.registrar_url else 'Unknown'}
    anonymous:                     No
    registered:                    {w.creation_date if w.creation_date else 'Unknown'}
    source:                        WHOIS
    nic-hdl:                       {w.admin_id if w.admin_id else 'Unknown'}
    type:                          ORGANIZATION
    contact:                       {w.admin_name if w.admin_name else 'Unknown'}
    address:                       {w.admin_street if w.admin_street else 'Unknown'}
    country:                       {w.admin_country if w.admin_country else 'Unknown'}
    phone:                         {w.admin_phone if w.admin_phone else 'Unknown'}
    e-mail:                        {w.admin_email if w.admin_email else 'Unknown'}
    registrar:                     {w.registrar}
    changed:                       {w.updated_date if w.updated_date else 'Unknown'}
    anonymous:                     NO
    obsoleted:                     NO
    eppstatus:                     {'associated' if w.status == 'active' else 'inactive'}
    eligstatus:                    {'identified' if w.status == 'active' else 'not identified'}
    reachstatus:                   {'identified' if w.status == 'active' else 'not identified'}
    source:                        WHOIS
    
    >>> Last update of WHOIS database: {now.strftime('%Y-%m-%dT%H:%M:%SZ')} <<<
    """
    
    return formatted_info
