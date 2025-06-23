from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def generate_html_report(payloads_dict, output_file="report.html", category="Payload Report"):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')

    output = template.render(
        categorized_payloads=payloads_dict,
        category=category,
        generated=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

    with open(output_file, 'w') as f:
        f.write(output)

    print(f"[+] HTML report saved as: {output_file}")
