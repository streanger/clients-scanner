import os
from pathlib import Path
from pydub import AudioSegment
from pydub.playback import play


os.chdir(str(Path(__file__).parent))

# filename = 'mixkit-long-pop-2358.wav'
# song = AudioSegment.from_wav(filename)

filename = '../clients_scanner/sounds/mixkit-message-pop-alert-2354.mp3'
song = AudioSegment.from_mp3(filename)

play(song)
