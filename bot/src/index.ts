import 'dotenv/config';
const token = process.env.BOT_TOKEN;
const miniAppUrl = process.env.MINI_APP_URL;
if (!token || !miniAppUrl) throw new Error('BOT_TOKEN and MINI_APP_URL are required.');
const api = `https://api.telegram.org/bot${token}`;
type Update = { message?: { chat:{id:number}; text?:string } };
async function send(chatId:number, text:string, openApp=false) { await fetch(`${api}/sendMessage`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ chat_id:chatId, text, reply_markup:openApp ? { inline_keyboard:[[{ text:'Open CL-Service', web_app:{url:miniAppUrl} }]] } : undefined }) }); }
export async function handleUpdate(update:Update) { const message=update.message; if(!message?.text) return; const commands:Record<string,string>={ '/help':'CL-Service help\nOpen the Mini App to create, manage, and track secure escrow deals.', '/profile':'Open CL-Service to view your profile and security settings.', '/deals':'Open CL-Service to view your active escrow deals.' }; if(message.text.startsWith('/start')) return send(message.chat.id,'Welcome to CL-Service\n\nA secure marketplace for escrow-protected transactions.\n\nOpen the application below to get started.',true); if(commands[message.text]) return send(message.chat.id,commands[message.text]); }
const run=async()=>{let offset=0; for(;;){const response=await fetch(`${api}/getUpdates?timeout=30&offset=${offset}`);const json=await response.json() as {result:Array<Update&{update_id:number}>};for(const update of json.result){offset=update.update_id+1;await handleUpdate(update)}}};run().catch(error=>{console.error(error);process.exit(1)});
