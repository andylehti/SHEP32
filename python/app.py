import html
import os
import sys
import traceback
import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import importlib.util

CORE_PATHS = [
    os.path.join(BASE_DIR, 'shep32.py'),
]

core = None
corePath = None
for path in CORE_PATHS:
    if os.path.exists(path):
        spec = importlib.util.spec_from_file_location('shep32core', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        core = module
        corePath = path
        break

if core is None:
    raise FileNotFoundError('Could not find shep32.py in the app folder.')

st.set_page_config(page_title='SHEP32', page_icon='🔒', layout='wide')

st.markdown(
    '''
    <style>
    .footer {position: fixed; left: 0; bottom: 0; width: 100%; background: white; color: black; text-align: center; padding: 8px; border-top: 1px solid #ddd; z-index: 999;}
    .stTextArea textarea, .stTextInput input {font-family: monospace;}
    </style>
    ''',
    unsafe_allow_html=True,
)

if 'mode' not in st.session_state:
    st.session_state.mode = 'Encrypt'


def cleanToken(text):
    return ''.join((text or '').split())


def renderTextBlock(text):
    safe = html.escape(text).replace('\n', '<br>')
    st.markdown(f"<div style='white-space: pre-wrap; overflow-wrap: break-word;'>{safe}</div>", unsafe_allow_html=True)


def keyModeValue(name):
    return 0 if name == 'SHEP32' else 333


def makeProgressBox():
    bar = st.progress(0)
    label = st.empty()

    def update(i, total, stage):
        total = max(int(total), 1)
        i = max(0, min(int(i), total))
        bar.progress(i / total)
        label.caption(f'{stage} ({i}/{total})')

    return update, bar, label


def friendlyError(err):
    return str(err).strip() or err.__class__.__name__


st.subheader('SHEP32 / SHEP333 Streamlit App', divider='rainbow')
st.caption(f'Loaded core: {os.path.basename(corePath)}')

col1, col2, col3, col4 = st.columns(4)
with col1:
    if st.button('Encrypt', use_container_width=True):
        st.session_state.mode = 'Encrypt'
with col2:
    if st.button('Decrypt', use_container_width=True):
        st.session_state.mode = 'Decrypt'
with col3:
    if st.button('Detached Decrypt', use_container_width=True):
        st.session_state.mode = 'Detached Decrypt'
with col4:
    if st.button('Key Tools', use_container_width=True):
        st.session_state.mode = 'Key Tools'

mode = st.session_state.mode

if mode == 'Encrypt':
    st.title('Encryption')
    plainText = st.text_area('Enter data to encrypt:', '', height=220)

    left, right = st.columns(2)
    with left:
        keyModeName = st.selectbox('Key type', ['SHEP32', 'SHEP333'], index=0)
        userKey = st.text_input('Key or passphrase (leave blank to auto-generate):', '')
        detached = st.checkbox('Detached output', value=False)
        compress = st.checkbox('Compress before encrypting', value=True)
    with right:
        chunkSize = st.number_input('Chunk size', min_value=1, value=2048, step=1)
        powBits = st.number_input('Proof-of-work bits', min_value=0, value=0, step=1)
        powStart = st.number_input('Proof-of-work start nonce', min_value=0, value=0, step=1)
        showProgress = st.checkbox('Show progress', value=True)

    if st.button('Encrypt Data', type='primary', use_container_width=True):
        if not plainText:
            st.warning('Enter data to encrypt.')
        else:
            try:
                progressFn = None
                if showProgress:
                    progressFn, _, _ = makeProgressBox()
                out, resolvedKey = core.encryptData(
                    plainText,
                    k=userKey or None,
                    keyMode=keyModeValue(keyModeName),
                    count=8,
                    detached=detached,
                    compress=compress,
                    chunkSize=int(chunkSize),
                    powBits=int(powBits),
                    powStart=int(powStart),
                    progress=progressFn,
                )

                st.markdown('**Resolved key:**')
                st.code(resolvedKey)

                if detached:
                    st.markdown('**Detached meta:**')
                    st.code(out['meta'])
                    st.markdown('**Detached body:**')
                    st.code(out['body'])
                else:
                    st.markdown('**Ciphertext envelope:**')
                    st.code(out)

                with st.expander('Preview decrypted text'):
                    preview = core.decryptData(out, resolvedKey, count=8)
                    renderTextBlock(preview)

            except Exception as err:
                st.error(friendlyError(err))
                st.code(traceback.format_exc())

elif mode == 'Decrypt':
    st.title('Decryption')
    cipherText = cleanToken(st.text_area('Enter ciphertext envelope:', '', height=220))
    keyModeName = st.selectbox('Key type', ['SHEP32', 'SHEP333'], index=0, key='decMode')
    userKey = st.text_input('Key or passphrase:', '', key='decKey')
    showProgress = st.checkbox('Show progress', value=True, key='decProgress')

    if st.button('Decrypt Data', type='primary', use_container_width=True):
        if not cipherText or not userKey:
            st.warning('Enter both ciphertext and key/passphrase.')
        else:
            try:
                progressFn = None
                if showProgress:
                    progressFn, _, _ = makeProgressBox()
                plain = core.decryptData(
                    cipherText,
                    userKey,
                    keyMode=keyModeValue(keyModeName),
                    count=8,
                    progress=progressFn,
                )
                st.markdown('**Decrypted data:**')
                renderTextBlock(plain)
            except Exception as err:
                st.error(friendlyError(err))
                st.code(traceback.format_exc())

elif mode == 'Detached Decrypt':
    st.title('Detached Decryption')
    body = cleanToken(st.text_area('Enter detached body:', '', height=180))
    meta = cleanToken(st.text_area('Enter detached meta:', '', height=180))
    keyModeName = st.selectbox('Key type', ['SHEP32', 'SHEP333'], index=0, key='detMode')
    userKey = st.text_input('Key or passphrase:', '', key='detKey')
    showProgress = st.checkbox('Show progress', value=True, key='detProgress')

    if st.button('Decrypt Detached Data', type='primary', use_container_width=True):
        if not body or not meta or not userKey:
            st.warning('Enter detached body, detached meta, and key/passphrase.')
        else:
            try:
                progressFn = None
                if showProgress:
                    progressFn, _, _ = makeProgressBox()
                plain = core.decryptData(
                    body,
                    userKey,
                    keyMode=keyModeValue(keyModeName),
                    count=8,
                    meta=meta,
                    progress=progressFn,
                )
                st.markdown('**Decrypted data:**')
                renderTextBlock(plain)
            except Exception as err:
                st.error(friendlyError(err))
                st.code(traceback.format_exc())

elif mode == 'Key Tools':
    st.title('Key Tools')
    tab1, tab2, tab3 = st.tabs(['Generate', 'Public Key', 'Sign / Verify'])

    with tab1:
        seedText = st.text_input('Source text or seed (blank = random):', '', key='genSeed')
        keyModeName = st.selectbox('Key type', ['SHEP32', 'SHEP333'], index=0, key='genMode')
        if st.button('Generate Key', use_container_width=True):
            try:
                out = core.generateKey(seedText or None, mode=keyModeValue(keyModeName), count=8)
                st.code(out)
            except Exception as err:
                st.error(friendlyError(err))

    with tab2:
        keyModeName = st.selectbox('Key type', ['SHEP32', 'SHEP333'], index=0, key='pubMode')
        srcKey = st.text_input('Key or passphrase:', '', key='pubKey')
        if st.button('Generate Public Key', use_container_width=True):
            try:
                out = core.generatePublicKey(srcKey or None, keyMode=keyModeValue(keyModeName), count=8)
                st.code(out)
            except Exception as err:
                st.error(friendlyError(err))

    with tab3:
        signModeName = st.selectbox('Key type', ['SHEP32', 'SHEP333'], index=0, key='signMode')
        signKey = st.text_input('Signing key or passphrase:', '', key='signKey')
        signText = st.text_area('Data to sign:', '', height=140, key='signText')
        if st.button('Sign Data', use_container_width=True):
            try:
                sig = core.signData(signText, signKey, keyMode=keyModeValue(signModeName), count=8)
                st.code(sig)
            except Exception as err:
                st.error(friendlyError(err))

        verifyText = st.text_area('Data to verify:', '', height=140, key='verifyText')
        signature = cleanToken(st.text_area('Signature:', '', height=120, key='verifySig'))
        publicKey = cleanToken(st.text_input('Public key:', '', key='verifyPub'))
        if st.button('Verify Signature', use_container_width=True):
            try:
                ok = core.verifySignature(verifyText, signature, publicKey)
                if ok:
                    st.success('Signature verified.')
                else:
                    st.error('Signature did not verify.')
            except Exception as err:
                st.error(friendlyError(err))

footer = """
<div class='footer'>
    <p>GitHub Repository: <a href='https://github.com/andylehti/SHEP32' target='_blank'>SHEP32</a></p>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
