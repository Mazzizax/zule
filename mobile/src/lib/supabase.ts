import { createClient } from '@supabase/supabase-js'
import AsyncStorage from '@react-native-async-storage/async-storage'

const SUPABASE_URL = 'https://sgjulzvgcyotebbexfue.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNnanVsenZnY3lvdGViYmV4ZnVlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MzY1MzM4NDIsImV4cCI6MjA1MjEwOTg0Mn0.jH2E3v8GWRZ29MXX_nwQV4JhRPcXq0G-DF6UkTLYenM'

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    storage: AsyncStorage,
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: false,
  },
})

export { SUPABASE_URL }
