from flask import Flask, render_template, jsonify
import threading
import yaml
import asyncio
from trap_listener import TrapListener
from trap_processor import TrapProcessor

app = Flask(__name__)

# Global variables to store our components
trap_listener = None
trap_processor = None

def load_config():
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/events')
def get_events():
    if trap_processor:
        return jsonify(trap_processor.to_dict())
    return jsonify({'events': []})

async def start_trap_listener():
    global trap_listener
    trap_listener = TrapListener()
    await trap_listener.start()

def start_components():
    global trap_listener, trap_processor
    
    # Initialize components
    trap_listener = TrapListener()
    trap_processor = TrapProcessor(trap_listener.trap_queue)
    
    # Start trap processor in a separate thread
    processor_thread = threading.Thread(target=trap_processor.process_queue)
    processor_thread.daemon = True
    processor_thread.start()
    
    # Start trap listener in a separate thread with asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    listener_thread = threading.Thread(target=loop.run_until_complete, args=(start_trap_listener(),))
    listener_thread.daemon = True
    listener_thread.start()

if __name__ == '__main__':
    config = load_config()
    start_components()
    app.run(host='0.0.0.0', port=config['trap_processor']['web_port']) 